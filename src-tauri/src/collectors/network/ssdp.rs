//! SSDP discovery and UPnP Internet Gateway Device queries.
//!
//! This is how SENTRY learns about the router as a *device* rather than just an
//! address, and -- far more importantly -- how it finds **port forwards**.
//!
//! A UPnP port mapping is a hole punched from the internet through to a machine
//! on the home network, usually created automatically by a game, a console or a
//! media server without anyone being told. It is one of the very few things
//! visible from inside a home network that genuinely indicates outside exposure.
//! Most home users have no idea these exist or how to look at them.
//!
//! Everything here is a request to the local router only. Nothing is sent to
//! the internet.

use std::net::UdpSocket;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::security::CollectorError;

/// The SSDP multicast group and port.
const SSDP_ADDR: &str = "239.255.255.250:1900";

/// How long to listen for responses. SSDP replies are staggered by the
/// `MX` value below, so this must exceed it.
const LISTEN_FOR: Duration = Duration::from_secs(4);

/// Asks responders to spread their replies over this many seconds, which is
/// the politeness mechanism built into SSDP.
const MX_SECONDS: u8 = 2;

/// Cap on a device description document. Routers return a few kilobytes;
/// anything far larger is malformed or hostile.
const MAX_DESCRIPTION_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsdpResponder {
    /// Address that answered.
    pub address: String,
    /// URL of the device description document.
    pub location: Option<String>,
    /// Advertised device or service type.
    pub service_type: Option<String>,
    /// The `SERVER` header, which usually names the firmware.
    pub server: Option<String>,
}

/// A port forward configured on the router.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortMapping {
    pub external_port: u16,
    pub internal_port: u16,
    pub internal_client: String,
    pub protocol: String,
    pub description: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsdpFacts {
    pub responders: Vec<SsdpResponder>,
    /// Router make and model, when the description document gives them.
    pub router_manufacturer: Option<String>,
    pub router_model: Option<String>,
    pub router_firmware: Option<String>,
    /// True when the router answered SSDP at all, i.e. UPnP is switched on.
    pub upnp_enabled: bool,
    /// Port forwards read from the gateway. `None` means the list could not be
    /// read -- which is not the same as there being none.
    pub port_mappings: Option<Vec<PortMapping>>,
    /// Why the mapping list is absent, when it is.
    pub mappings_unavailable_reason: Option<String>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

impl SsdpFacts {
    /// Mappings that are switched on, which are the ones that actually expose
    /// something.
    pub fn active_mappings(&self) -> Vec<&PortMapping> {
        self.port_mappings
            .as_ref()
            .map(|m| m.iter().filter(|m| m.enabled).collect())
            .unwrap_or_default()
    }
}

/// Discover UPnP devices and read the gateway's port mappings.
pub fn collect(gateway: Option<&str>) -> Result<SsdpFacts, CollectorError> {
    let mut facts = SsdpFacts {
        collected_at: chrono::Utc::now().to_rfc3339(),
        evidence: vec![
            "Protocol: SSDP (UPnP discovery) on 239.255.255.250:1900".to_string(),
            "Requests go to the local network only".to_string(),
        ],
        ..Default::default()
    };

    facts.responders = discover()?;
    facts.upnp_enabled = !facts.responders.is_empty();

    facts.evidence.push(format!(
        "{} device(s) answered UPnP discovery",
        facts.responders.len()
    ));

    if !facts.upnp_enabled {
        facts.mappings_unavailable_reason = Some(
            "Nothing on the network answered UPnP discovery, so port forwards could not be read. \
             This often means UPnP is turned off on the router, which is the safer setting."
                .to_string(),
        );
        return Ok(facts);
    }

    // Prefer a responder that is the gateway; a media server answering SSDP is
    // not the router.
    let gateway_responder = facts
        .responders
        .iter()
        .find(|r| gateway.is_some_and(|g| r.address.starts_with(g)))
        .or_else(|| {
            facts.responders.iter().find(|r| {
                r.service_type
                    .as_deref()
                    .is_some_and(|t| t.contains("InternetGatewayDevice"))
            })
        })
        .cloned();

    let Some(responder) = gateway_responder else {
        facts.mappings_unavailable_reason = Some(
            "No device identified itself as the internet gateway, so port forwards could not be read."
                .to_string(),
        );
        return Ok(facts);
    };

    if let Some(server) = &responder.server {
        facts.router_firmware = Some(server.clone());
        facts.evidence.push(format!("Router reports: {server}"));
    }

    let Some(location) = &responder.location else {
        facts.mappings_unavailable_reason =
            Some("The gateway did not provide a description address.".to_string());
        return Ok(facts);
    };

    facts
        .evidence
        .push(format!("Device description: {location}"));

    match fetch_description(location) {
        Ok(description) => {
            facts.router_manufacturer = extract_tag(&description, "manufacturer");
            facts.router_model = extract_tag(&description, "modelName")
                .or_else(|| extract_tag(&description, "modelDescription"));

            if let Some(make) = &facts.router_manufacturer {
                facts.evidence.push(format!("Manufacturer: {make}"));
            }
            if let Some(model) = &facts.router_model {
                facts.evidence.push(format!("Model: {model}"));
            }

            // Reading the mapping table needs the control URL from the
            // description, which varies by manufacturer.
            match control_url(location, &description) {
                Some(control) => {
                    facts.evidence.push(format!("Control endpoint: {control}"));
                    match read_mappings(&control) {
                        Ok(mappings) => {
                            facts
                                .evidence
                                .push(format!("{} port forward(s) configured", mappings.len()));
                            facts.port_mappings = Some(mappings);
                        }
                        Err(e) => {
                            facts.mappings_unavailable_reason = Some(format!(
                                "The router did not return its port forward list: {e}"
                            ));
                        }
                    }
                }
                None => {
                    facts.mappings_unavailable_reason = Some(
                        "The router's description did not include a port-forwarding service, so \
                         its forwards could not be read."
                            .to_string(),
                    );
                }
            }
        }
        Err(e) => {
            facts.mappings_unavailable_reason =
                Some(format!("The router's description could not be read: {e}"));
        }
    }

    Ok(facts)
}

/// Send an SSDP M-SEARCH and collect the replies.
fn discover() -> Result<Vec<SsdpResponder>, CollectorError> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| CollectorError::Unavailable(format!("Could not open a UDP socket: {e}")))?;

    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| CollectorError::Unavailable(format!("Could not configure the socket: {e}")))?;

    let request = format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {SSDP_ADDR}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {MX_SECONDS}\r\n\
         ST: upnp:rootdevice\r\n\r\n"
    );

    socket
        .send_to(request.as_bytes(), SSDP_ADDR)
        .map_err(|e| CollectorError::Unavailable(format!("Could not send UPnP discovery: {e}")))?;

    let deadline = std::time::Instant::now() + LISTEN_FOR;
    let mut responders: Vec<SsdpResponder> = Vec::new();
    let mut buffer = [0u8; 2048];

    while std::time::Instant::now() < deadline {
        match socket.recv_from(&mut buffer) {
            Ok((len, from)) => {
                let text = String::from_utf8_lossy(&buffer[..len]);
                let responder = SsdpResponder {
                    address: from.ip().to_string(),
                    location: header(&text, "LOCATION"),
                    service_type: header(&text, "ST").or_else(|| header(&text, "NT")),
                    server: header(&text, "SERVER"),
                };

                // One device answers several times; keep one entry each.
                if !responders
                    .iter()
                    .any(|r| r.address == responder.address && r.location == responder.location)
                {
                    responders.push(responder);
                }
            }
            // A timeout just means nothing arrived in this window.
            Err(_) => continue,
        }
    }

    Ok(responders)
}

/// Case-insensitive HTTP-style header lookup.
fn header(response: &str, name: &str) -> Option<String> {
    let wanted = name.to_ascii_lowercase();
    response.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim().to_ascii_lowercase() == wanted).then(|| value.trim().to_string())
    })
}

fn fetch_description(url: &str) -> Result<String, CollectorError> {
    let mut response = ureq::get(url)
        .call()
        .map_err(|e| CollectorError::Unavailable(format!("{e}")))?;

    response
        .body_mut()
        .with_config()
        .limit(MAX_DESCRIPTION_BYTES)
        .read_to_string()
        .map_err(|e| CollectorError::Malformed {
            origin: "UPnP device description".to_string(),
            detail: e.to_string(),
        })
}

/// Pull the text of the first `<tag>` in an XML document.
///
/// A deliberate non-parse: device descriptions come from consumer routers whose
/// XML is frequently malformed, and a strict parser would reject documents a
/// simple scan reads fine. Values are only ever displayed, never executed.
pub fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;

    let value = xml[start..end].trim();
    // Cap the length: this is router-controlled input heading for the UI.
    (!value.is_empty()).then(|| value.chars().take(200).collect())
}

/// Build the absolute control URL for the port-mapping service.
pub fn control_url(location: &str, description: &str) -> Option<String> {
    // Both the older WANIPConnection and the WANPPPConnection services expose
    // the mapping table; routers implement one or the other.
    let control = ["WANIPConnection", "WANPPPConnection"]
        .iter()
        .find_map(|service| control_for_service(description, service))?;

    resolve_url(location, &control)
}

fn control_for_service(description: &str, service: &str) -> Option<String> {
    // Find the service block, then its controlURL.
    let marker = description.find(service)?;
    let rest = &description[marker..];
    let end = rest.find("</service>").unwrap_or(rest.len());
    extract_tag(&rest[..end], "controlURL")
}

/// Resolve a possibly-relative URL against the description's location.
pub fn resolve_url(base: &str, path: &str) -> Option<String> {
    if path.starts_with("http://") || path.starts_with("https://") {
        return Some(path.to_string());
    }

    // Keep scheme://host:port from the base.
    let scheme_end = base.find("://")? + 3;
    let authority_end = base[scheme_end..]
        .find('/')
        .map(|i| scheme_end + i)
        .unwrap_or(base.len());
    let origin = &base[..authority_end];

    Some(if path.starts_with('/') {
        format!("{origin}{path}")
    } else {
        format!("{origin}/{path}")
    })
}

/// Walk the router's port-mapping table.
///
/// UPnP has no "list all" call; entries are read by index until the router
/// reports there is no such entry.
fn read_mappings(control: &str) -> Result<Vec<PortMapping>, CollectorError> {
    const MAX_ENTRIES: u32 = 200;

    let mut mappings = Vec::new();

    for index in 0..MAX_ENTRIES {
        let body = format!(
            r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <s:Body>
  <u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
   <NewPortMappingIndex>{index}</NewPortMappingIndex>
  </u:GetGenericPortMappingEntry>
 </s:Body>
</s:Envelope>"#
        );

        let response = ureq::post(control)
            .header("Content-Type", "text/xml; charset=\"utf-8\"")
            .header(
                "SOAPAction",
                "\"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry\"",
            )
            .send(body);

        let Ok(mut response) = response else {
            // The router refuses once the index runs past the end, which is how
            // the walk terminates. An error on the very first entry means the
            // table could not be read at all.
            if index == 0 {
                return Err(CollectorError::Unavailable(
                    "The router refused the port-forward query.".into(),
                ));
            }
            break;
        };

        let Ok(text) = response
            .body_mut()
            .with_config()
            .limit(MAX_DESCRIPTION_BYTES)
            .read_to_string()
        else {
            break;
        };

        // A SOAP fault also ends the walk.
        if text.contains("SpecifiedArrayIndexInvalid") || text.contains("<s:Fault>") {
            break;
        }

        let Some(external) = extract_tag(&text, "NewExternalPort").and_then(|v| v.parse().ok())
        else {
            break;
        };

        mappings.push(PortMapping {
            external_port: external,
            internal_port: extract_tag(&text, "NewInternalPort")
                .and_then(|v| v.parse().ok())
                .unwrap_or(external),
            internal_client: extract_tag(&text, "NewInternalClient").unwrap_or_default(),
            protocol: extract_tag(&text, "NewProtocol").unwrap_or_else(|| "TCP".to_string()),
            description: extract_tag(&text, "NewPortMappingDescription").unwrap_or_default(),
            enabled: extract_tag(&text, "NewEnabled").as_deref() != Some("0"),
        });
    }

    Ok(mappings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESCRIPTION: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>ASUS Router</friendlyName>
    <manufacturer>ASUSTeK Computer Inc.</manufacturer>
    <modelName>RT-AX88U</modelName>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <controlURL>/upnp/control/WANIPConn1</controlURL>
      </service>
    </serviceList>
  </device>
</root>"#;

    #[test]
    fn extracts_tags_from_a_description() {
        assert_eq!(
            extract_tag(DESCRIPTION, "manufacturer").as_deref(),
            Some("ASUSTeK Computer Inc.")
        );
        assert_eq!(
            extract_tag(DESCRIPTION, "modelName").as_deref(),
            Some("RT-AX88U")
        );
        assert_eq!(extract_tag(DESCRIPTION, "nonexistent"), None);
    }

    #[test]
    fn tag_values_are_length_capped() {
        // The router controls this text and it ends up in the UI.
        let long = format!("<modelName>{}</modelName>", "A".repeat(5000));
        assert_eq!(extract_tag(&long, "modelName").unwrap().len(), 200);
    }

    #[test]
    fn empty_tags_are_treated_as_absent() {
        assert_eq!(extract_tag("<modelName>   </modelName>", "modelName"), None);
    }

    #[test]
    fn builds_an_absolute_control_url_from_a_relative_one() {
        let url = control_url("http://192.168.50.1:1990/rootDesc.xml", DESCRIPTION);
        assert_eq!(
            url.as_deref(),
            Some("http://192.168.50.1:1990/upnp/control/WANIPConn1")
        );
    }

    #[test]
    fn resolves_urls_of_every_shape() {
        let base = "http://192.168.1.1:5000/desc.xml";
        assert_eq!(
            resolve_url(base, "/ctl/IPConn").as_deref(),
            Some("http://192.168.1.1:5000/ctl/IPConn")
        );
        assert_eq!(
            resolve_url(base, "ctl/IPConn").as_deref(),
            Some("http://192.168.1.1:5000/ctl/IPConn")
        );
        // An already-absolute URL is left alone.
        assert_eq!(
            resolve_url(base, "http://10.0.0.1/ctl").as_deref(),
            Some("http://10.0.0.1/ctl")
        );
    }

    #[test]
    fn a_description_with_no_mapping_service_yields_no_control_url() {
        let bare = "<root><device><manufacturer>X</manufacturer></device></root>";
        assert_eq!(control_url("http://192.168.1.1/d.xml", bare), None);
    }

    #[test]
    fn headers_are_matched_case_insensitively() {
        let response = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/d.xml\r\nServer: Linux/3.4 UPnP/1.0\r\n\r\n";
        assert_eq!(
            header(response, "location").as_deref(),
            Some("http://192.168.1.1/d.xml")
        );
        assert_eq!(
            header(response, "SERVER").as_deref(),
            Some("Linux/3.4 UPnP/1.0")
        );
        assert_eq!(header(response, "missing"), None);
    }

    #[test]
    fn active_mappings_exclude_disabled_ones() {
        let facts = SsdpFacts {
            port_mappings: Some(vec![
                PortMapping {
                    external_port: 32400,
                    internal_port: 32400,
                    internal_client: "192.168.1.50".into(),
                    protocol: "TCP".into(),
                    description: "Plex".into(),
                    enabled: true,
                },
                PortMapping {
                    external_port: 25565,
                    internal_port: 25565,
                    internal_client: "192.168.1.51".into(),
                    protocol: "TCP".into(),
                    description: "Old rule".into(),
                    enabled: false,
                },
            ]),
            ..Default::default()
        };

        assert_eq!(facts.active_mappings().len(), 1);
        assert_eq!(facts.active_mappings()[0].description, "Plex");
    }

    #[test]
    fn an_absent_mapping_list_is_not_an_empty_one() {
        // "We could not read the forwards" and "there are no forwards" are
        // different answers and must not collapse.
        let facts = SsdpFacts {
            port_mappings: None,
            mappings_unavailable_reason: Some("router refused".into()),
            ..Default::default()
        };
        assert!(facts.active_mappings().is_empty());
        assert!(facts.port_mappings.is_none());
        assert!(facts.mappings_unavailable_reason.is_some());
    }
}
