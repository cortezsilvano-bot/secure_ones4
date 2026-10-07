//! SSDP discovery and UPnP Internet Gateway Device queries.
//!
//! This is how SENTRY learns about the router as a *device* rather than just an
//! address, and -- far more importantly -- how it finds **port forwards**.
//!
//! A UPnP mapping configures forwarding to a machine on the home network.
//! It does not establish public Internet reachability: upstream filtering and
//! NAT can prevent access. The table may omit other forwarding mechanisms.
//!
//! Everything here is a request to the local router only. Nothing is sent to
//! the internet.

use std::net::UdpSocket;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::router::probe::ProbeContext;
use crate::security::{CollectorError, Known};

/// The SSDP multicast group and port.
const SSDP_ADDR: &str = "239.255.255.250:1900";

/// How long to listen for responses. SSDP replies are staggered by the
/// `MX` value below, so this must exceed it.
const LISTEN_FOR: Duration = Duration::from_secs(4);

/// Asks responders to spread their replies over this many seconds, which is
/// the politeness mechanism built into SSDP.
const MX_SECONDS: u8 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsdpResponder {
    /// Address that answered.
    pub address: String,
    /// URL of the device description document.
    pub location: Option<String>,
    /// Advertised device or service type.
    pub service_type: Option<String>,
    /// The advertised software stack; not a verified installed firmware version.
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
    #[serde(default)]
    pub server_banner: Option<String>,
    /// A reply from the selected gateway. Silence does not establish disabled UPnP.
    #[serde(default)]
    pub upnp_discovery: Known<bool>,
    /// Port forwards read from the gateway. `None` means the list could not be
    /// read -- which is not the same as there being none.
    pub port_mappings: Option<Vec<PortMapping>>,
    /// Why the mapping list is absent, when it is.
    pub mappings_unavailable_reason: Option<String>,
    pub evidence: Vec<String>,
    pub collected_at: String,
}

impl SsdpFacts {
    /// Mappings reported as enabled; public reachability is not established.
    pub fn active_mappings(&self) -> Vec<&PortMapping> {
        self.port_mappings
            .as_ref()
            .map(|m| m.iter().filter(|m| m.enabled).collect())
            .unwrap_or_default()
    }
}

/// Discover UPnP devices and read the gateway's port mappings.
pub fn collect(gateway: Option<&str>) -> Result<SsdpFacts, CollectorError> {
    let interfaces = super::interfaces::collect()?;
    let target = super::router::target::candidates(&interfaces, 1)
        .into_iter()
        .find(|t| gateway.is_some_and(|g| g == t.address.to_string()))
        .ok_or_else(|| {
            CollectorError::Unavailable("No supported local gateway selected.".into())
        })?;
    collect_target(&ProbeContext::new(&target))
}

pub(crate) fn collect_target(ctx: &ProbeContext) -> Result<SsdpFacts, CollectorError> {
    let gateway = ctx.address.to_string();
    let mut facts = SsdpFacts {
        collected_at: chrono::Utc::now().to_rfc3339(),
        evidence: vec![
            "Protocol: SSDP (UPnP discovery) on 239.255.255.250:1900".to_string(),
            "Requests go to the local network only".to_string(),
        ],
        ..Default::default()
    };

    facts.responders = discover(ctx)?;

    facts.evidence.push(format!(
        "{} device(s) answered UPnP discovery",
        facts.responders.len()
    ));

    // Never attribute another device's reply to the selected gateway.
    let Some(responder) = record_gateway_discovery(&mut facts, Some(&gateway)) else {
        return Ok(facts);
    };

    if let Some(server) = &responder.server {
        facts.server_banner = Some(server.clone());
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

    match fetch_description(ctx, location) {
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
            match mapping_service(location, &description) {
                Some((control, service)) => {
                    facts.evidence.push(format!("Control endpoint: {control}"));
                    match read_mappings(ctx, &control, &service) {
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

fn select_gateway<'a>(
    responders: &'a [SsdpResponder],
    gateway: Option<&str>,
) -> Option<&'a SsdpResponder> {
    let gateway = gateway?.parse::<std::net::IpAddr>().ok()?;
    responders
        .iter()
        .find(|r| r.address.parse::<std::net::IpAddr>().ok() == Some(gateway))
}

fn record_gateway_discovery(facts: &mut SsdpFacts, gateway: Option<&str>) -> Option<SsdpResponder> {
    let responder = select_gateway(&facts.responders, gateway).cloned();
    if responder.is_some() {
        facts.upnp_discovery = Known::Known(true);
    } else {
        let reason = "The selected gateway did not answer discovery. UPnP may be disabled, filtered or unavailable; its configuration is unknown.";
        facts.upnp_discovery = Known::Unavailable(reason.into());
        facts.mappings_unavailable_reason = Some(reason.into());
    }
    responder
}

/// Send an SSDP M-SEARCH and collect the replies.
fn discover(ctx: &ProbeContext) -> Result<Vec<SsdpResponder>, CollectorError> {
    if cfg!(test) {
        return Err(CollectorError::Unsupported(
            "SSDP multicast is disabled in unit-test builds.".into(),
        ));
    }
    ctx.reserve()?;
    let socket = UdpSocket::bind((ctx.local_address, 0))
        .map_err(|e| CollectorError::Unavailable(format!("Could not open a UDP socket: {e}")))?;

    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| CollectorError::Unavailable(format!("Could not configure the socket: {e}")))?;

    socket.set_multicast_ttl_v4(1).map_err(|e| {
        CollectorError::Unavailable(format!("Could not restrict discovery scope: {e}"))
    })?;
    socket2::SockRef::from(&socket)
        .set_multicast_if_v4(&ctx.local_address)
        .map_err(|e| {
            CollectorError::Unavailable(format!("Could not select discovery interface: {e}"))
        })?;

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
        ctx.check()?;
        socket
            .set_read_timeout(Some(ctx.remaining()?.min(Duration::from_millis(250))))
            .map_err(|e| CollectorError::Unavailable(e.to_string()))?;
        match socket.recv_from(&mut buffer) {
            Ok((len, from)) => {
                if from.ip() != std::net::IpAddr::V4(ctx.address) || responders.len() >= 64 {
                    continue;
                }
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
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(e) => {
                return Err(CollectorError::Unavailable(format!(
                    "Discovery receive failed: {e}"
                )))
            }
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

fn fetch_description(ctx: &ProbeContext, url: &str) -> Result<String, CollectorError> {
    let (status, body) = ctx.http(url, None)?;
    if status != 200 {
        return Err(CollectorError::Unavailable(format!(
            "Device description returned HTTP {status}."
        )));
    }
    Ok(body)
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
    mapping_service(location, description).map(|(url, _)| url)
}

fn mapping_service(location: &str, description: &str) -> Option<(String, String)> {
    for block in description.split("<service>").skip(1) {
        let end = block.find("</service>")?;
        let block = &block[..end];
        let Some(service) = extract_tag(block, "serviceType") else {
            continue;
        };
        if !matches!(
            service.as_str(),
            "urn:schemas-upnp-org:service:WANIPConnection:1"
                | "urn:schemas-upnp-org:service:WANIPConnection:2"
                | "urn:schemas-upnp-org:service:WANPPPConnection:1"
        ) {
            continue;
        }
        let control = extract_tag(block, "controlURL")?;
        return Some((resolve_url(location, &control)?, service));
    }
    None
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
fn read_mappings(
    ctx: &ProbeContext,
    control: &str,
    service: &str,
) -> Result<Vec<PortMapping>, CollectorError> {
    const MAX_ENTRIES: u32 = 200;

    let mut mappings = Vec::new();
    for index in 0..MAX_ENTRIES {
        let body = format!(
            r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <s:Body>
  <u:GetGenericPortMappingEntry xmlns:u="{service}">
   <NewPortMappingIndex>{index}</NewPortMappingIndex>
  </u:GetGenericPortMappingEntry>
 </s:Body>
</s:Envelope>"#
        );

        let (status, text) = ctx.http(
            control,
            Some((&format!("\"{service}#GetGenericPortMappingEntry\""), &body)),
        )?;

        match parse_mapping_response(status, &text)? {
            Some(mapping) => mappings.push(mapping),
            None => return Ok(mappings),
        }
    }

    Err(CollectorError::Unavailable(
        "The port-forward enumeration limit was reached; the list is incomplete.".into(),
    ))
}

/// Only the standardized end-of-table fault establishes a complete list.
/// See https://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v1-Service.pdf, section 2.4.14.
fn parse_mapping_response(status: u16, text: &str) -> Result<Option<PortMapping>, CollectorError> {
    let malformed = || CollectorError::Malformed {
        origin: "UPnP port mapping".into(),
        detail: "Missing or invalid mapping fields; the list is incomplete.".into(),
    };
    if let Some(code) = extract_tag(text, "errorCode") {
        if code == "713" && (status == 500 || status == 200) {
            return Ok(None);
        }
        return Err(CollectorError::Unavailable(format!(
            "The router returned UPnP error {code}; the mapping list is unavailable."
        )));
    }
    if status != 200 {
        return Err(CollectorError::Unavailable(format!(
            "Port-forward query returned HTTP {status}."
        )));
    }
    let port = |tag| {
        extract_tag(text, tag)
            .and_then(|v| v.parse::<u16>().ok())
            .filter(|p| *p != 0)
            .ok_or_else(malformed)
    };
    let protocol = extract_tag(text, "NewProtocol")
        .ok_or_else(malformed)?
        .to_ascii_uppercase();
    if !matches!(protocol.as_str(), "TCP" | "UDP") {
        return Err(malformed());
    }
    let enabled = match extract_tag(text, "NewEnabled").as_deref() {
        Some("1" | "true") => true,
        Some("0" | "false") => false,
        _ => return Err(malformed()),
    };
    Ok(Some(PortMapping {
        external_port: port("NewExternalPort")?,
        internal_port: port("NewInternalPort")?,
        internal_client: extract_tag(text, "NewInternalClient").ok_or_else(malformed)?,
        protocol,
        description: extract_tag(text, "NewPortMappingDescription").unwrap_or_default(),
        enabled,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_never_starts_ssdp_discovery() {
        let ctx = super::super::router::probe::fixture(std::net::Ipv4Addr::LOCALHOST);
        assert!(matches!(
            discover(&ctx),
            Err(CollectorError::Unsupported(_))
        ));
        assert_eq!(ctx.request_count(), 0);
    }

    const MAPPING: &str = "<NewExternalPort>4567</NewExternalPort><NewInternalPort>22</NewInternalPort><NewInternalClient>192.168.1.20</NewInternalClient><NewProtocol>TCP</NewProtocol><NewEnabled>1</NewEnabled>";

    #[test]
    fn silence_or_other_devices_never_establish_disabled_or_enabled_gateway_upnp() {
        let mut facts = SsdpFacts::default();
        assert!(record_gateway_discovery(&mut facts, Some("192.168.1.1")).is_none());
        assert!(matches!(facts.upnp_discovery, Known::Unavailable(_)));
        facts.responders.push(SsdpResponder {
            address: "192.168.1.10".into(),
            location: None,
            service_type: Some("InternetGatewayDevice".into()),
            server: None,
        });
        assert!(record_gateway_discovery(&mut facts, Some("192.168.1.1")).is_none());
        assert!(matches!(facts.upnp_discovery, Known::Unavailable(_)));
        facts.responders[0].address = "192.168.1.1".into();
        assert!(record_gateway_discovery(&mut facts, Some("192.168.1.1")).is_some());
        assert!(matches!(facts.upnp_discovery, Known::Known(true)));
    }

    #[test]
    fn only_a_specific_end_of_table_fault_completes_enumeration() {
        assert!(parse_mapping_response(500, "<errorCode>713</errorCode>")
            .unwrap()
            .is_none());
        for (status, body) in [
            (500, "<errorCode>501</errorCode>"),
            (200, "<s:Fault/>"),
            (401, ""),
            (200, ""),
            (302, ""),
        ] {
            assert!(parse_mapping_response(status, body).is_err());
        }
    }

    #[test]
    fn missing_mapping_fields_are_not_filled_with_security_assumptions() {
        let m = parse_mapping_response(200, MAPPING).unwrap().unwrap();
        assert_eq!((m.external_port, m.internal_port), (4567, 22));
        assert!(m.enabled);
        for tag in [
            "NewInternalPort",
            "NewProtocol",
            "NewEnabled",
            "NewInternalClient",
        ] {
            let value = extract_tag(MAPPING, tag).unwrap();
            let incomplete = MAPPING.replace(&format!("<{tag}>{value}</{tag}>"), "");
            assert!(
                parse_mapping_response(200, &incomplete).is_err(),
                "missing {tag}"
            );
        }
        assert!(parse_mapping_response(
            200,
            &MAPPING.replace("<NewEnabled>1", "<NewEnabled>invalid")
        )
        .is_err());
    }

    fn mock_mapping_server(responses: Vec<(u16, String)>) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{BufRead, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/control", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let handle = std::thread::spawn(move || {
            for (status, body) in responses {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && std::time::Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        Err(e) => panic!("mock accept: {e}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(&mut stream);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                reader.read_exact(&mut vec![0; length]).unwrap();
                write!(stream, "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (url, handle)
    }

    #[test]
    fn http_fault_can_establish_an_empty_table() {
        let (url, server) = mock_mapping_server(vec![(500, "<errorCode>713</errorCode>".into())]);
        let result = read_mappings(
            &super::super::router::probe::fixture(std::net::Ipv4Addr::LOCALHOST),
            &url,
            "urn:schemas-upnp-org:service:WANIPConnection:1",
        );
        server.join().unwrap();
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn a_failed_second_query_cannot_turn_a_partial_table_into_a_complete_one() {
        let (url, server) = mock_mapping_server(vec![
            (200, MAPPING.into()),
            (500, "<errorCode>501</errorCode>".into()),
        ]);
        let result = read_mappings(
            &super::super::router::probe::fixture(std::net::Ipv4Addr::LOCALHOST),
            &url,
            "urn:schemas-upnp-org:service:WANIPConnection:1",
        );
        server.join().unwrap();
        assert!(result.is_err());
    }

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
    fn mapping_queries_use_the_advertised_supported_service() {
        for service in [
            "WANIPConnection:1",
            "WANIPConnection:2",
            "WANPPPConnection:1",
        ] {
            let description = DESCRIPTION.replace("WANIPConnection:1", service);
            let (_, namespace) =
                mapping_service("http://192.168.1.1/desc.xml", &description).unwrap();
            assert_eq!(namespace, format!("urn:schemas-upnp-org:service:{service}"));
        }
        let unsupported = DESCRIPTION.replace("WANIPConnection:1", "UntrustedService:1");
        assert!(mapping_service("http://192.168.1.1/desc.xml", &unsupported).is_none());
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
