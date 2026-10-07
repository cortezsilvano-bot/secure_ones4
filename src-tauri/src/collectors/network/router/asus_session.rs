//! Opt-in, single-use session for the source-reviewed GNUton build.
//! The endpoint vocabulary is private: callers cannot supply URLs or NVRAM keys.
use super::{
    asus, identity::RouterIdentity, probe::ProbeContext, provider::RouterProvider,
    target::RouterTarget, RouterFacts,
};
use crate::security::{CollectorError, Known};
use base64::Engine;
use parking_lot::Mutex;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LoginOptions {
    pub username: String,
    pub password: String,
    pub https_port: u16,
    /// Explicitly supplied public trust certificate; never fetched automatically.
    pub certificate_pem: String,
    #[serde(default)]
    pub support_region: super::intelligence::SupportRegion,
}
impl Drop for LoginOptions {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}
impl LoginOptions {
    fn validate(&self) -> Result<(), CollectorError> {
        let printable =
            |s: &str| !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| (32..=126).contains(&b));
        if self.https_port == 0
            || !printable(&self.username)
            || self.username.contains(':')
            || self.username.trim() != self.username
            || !printable(&self.password)
            || self.certificate_pem.len() > 16 * 1024
            || self.certificate_pem.contains("PRIVATE KEY")
        {
            return Err(failure("Invalid login input. Use a nonzero HTTPS port, printable ASCII credentials (up to 128 characters), and a public PEM certificate only."));
        }
        Ok(())
    }
}

pub struct AsusProvider(Mutex<Option<LoginOptions>>);
impl AsusProvider {
    pub fn new(options: LoginOptions) -> Result<Self, CollectorError> {
        options.validate()?;
        Ok(Self(Mutex::new(Some(options))))
    }
}
impl RouterProvider for AsusProvider {
    fn id(&self) -> &'static str {
        "asus_gnuton_388_9_2"
    }
    fn collect(
        &self,
        target: &RouterTarget,
        ctx: &ProbeContext,
    ) -> Result<RouterFacts, CollectorError> {
        ctx.check()?;
        let options = self
            .0
            .lock()
            .take()
            .ok_or_else(|| failure("This login approval has already been consumed."))?;
        let mut transport = Https::new(target, ctx, &options)?;
        collect_with(target, ctx, &options, &mut transport)
    }
}

fn failure(message: &str) -> CollectorError {
    CollectorError::Unavailable(message.into())
}

const IDENTITY: &str = "/appGet.cgi?hook=nvram_get(productid)%3Bnvram_get(firmver)%3Bnvram_get(buildno)%3Bnvram_get(extendno)%3Bnvram_get(swpjverno)%3Bnvram_get(sw_mode)";
const SETTINGS: &str =
    "/appGet.cgi?hook=nvram_get(fw_enable_x)%3Bnvram_get(ipv6_fw_enable)%3Bnvram_get(misc_http_x)";
enum Endpoint {
    Login,
    Identity,
    Settings,
    WirelessInventory,
    WirelessBatch(super::asus_wireless::Batch),
    Logout,
}
impl Endpoint {
    fn path(&self) -> &str {
        match self {
            Self::Login => "/login.cgi",
            Self::Identity => IDENTITY,
            Self::Settings => SETTINGS,
            Self::WirelessInventory => super::asus_wireless::INVENTORY_PATH,
            Self::WirelessBatch(batch) => &batch.path,
            Self::Logout => "/Logout.asp",
        }
    }
}
struct Reply {
    status: u16,
    cookie: Option<Zeroizing<String>>,
    body: Zeroizing<String>,
}
trait Transport {
    fn exchange(
        &mut self,
        endpoint: Endpoint,
        authorization: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Reply, CollectorError>;
}

struct Https<'a> {
    origin: String,
    ctx: &'a ProbeContext,
    tls: ureq::tls::TlsConfig,
}
impl<'a> Https<'a> {
    fn new(
        target: &RouterTarget,
        ctx: &'a ProbeContext,
        options: &LoginOptions,
    ) -> Result<Self, CollectorError> {
        let mut tls = ureq::tls::TlsConfig::builder();
        if !options.certificate_pem.trim().is_empty() {
            if options
                .certificate_pem
                .matches("-----BEGIN CERTIFICATE-----")
                .count()
                != 1
            {
                return Err(failure("Supply exactly one public trust certificate."));
            }
            let cert = ureq::tls::Certificate::from_pem(options.certificate_pem.as_bytes())
                .map_err(|_| failure("The public PEM certificate could not be parsed."))?;
            tls = tls.root_certs(ureq::tls::RootCerts::new_with_certs(&[cert]));
        }
        Ok(Self {
            origin: format!("https://{}:{}", target.address, options.https_port),
            ctx,
            tls: tls.build(),
        })
    }
}
impl Transport for Https<'_> {
    fn exchange(
        &mut self,
        endpoint: Endpoint,
        authorization: Option<&str>,
        cookie: Option<&str>,
    ) -> Result<Reply, CollectorError> {
        let url = format!("{}{}", self.origin, endpoint.path());
        self.ctx.validate_url(&url)?;
        let timeout = self.ctx.reserve()?;
        // A fresh agent avoids pooled-connection retries and persistent cookies.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .tls_config(self.tls.clone())
            .user_agent("SENTRY/0.1")
            .build()
            .into();
        let referer = format!("{}/Main_Login.asp", self.origin);
        let response = if matches!(endpoint, Endpoint::Login) {
            agent.post(&url).header("Referer", &referer).send_form([
                ("login_authorization", authorization.unwrap_or("")),
                ("next_page", "index.asp"),
                ("login_captcha", ""),
            ])
        } else {
            agent
                .get(&url)
                .header("Referer", &referer)
                .header("Cookie", cookie.unwrap_or(""))
                .call()
        };
        self.ctx.check()?;
        // Never return library errors: they may contain request metadata.
        let mut response = response.map_err(|_| failure("ASUS HTTPS request failed. Check the port and trusted certificate, including its validity and gateway IP identity. No retry was attempted."))?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err(failure("ASUS redirects are not followed."));
        }
        let mut token = None;
        if matches!(endpoint, Endpoint::Login) {
            for header in response.headers().get_all("set-cookie") {
                if let Ok(header) = header.to_str() {
                    if let Some(value) = parse_cookie(header) {
                        if token.is_some() {
                            return Err(failure("Ambiguous ASUS session cookie."));
                        }
                        token = Some(value);
                    }
                }
            }
        }
        let body = Zeroizing::new(
            response
                .body_mut()
                .with_config()
                .limit(16 * 1024)
                .read_to_string()
                .map_err(|_| failure("ASUS response was incomplete or too large."))?,
        );
        self.ctx.check()?;
        self.ctx.record_http_response(&url)?;
        Ok(Reply {
            status,
            cookie: token,
            body,
        })
    }
}

fn parse_cookie(header: &str) -> Option<Zeroizing<String>> {
    if header.chars().any(char::is_control) {
        return None;
    }
    let pair = header.split(';').next()?.trim();
    let token = pair.strip_prefix("asus_token=")?;
    if !(16..=128).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    Some(Zeroizing::new(pair.to_string()))
}

#[derive(Deserialize)]
struct IdentityResponse {
    productid: String,
    firmver: String,
    buildno: String,
    extendno: String,
    #[serde(default)]
    swpjverno: String,
    sw_mode: String,
}

fn reviewed_identity(body: &str) -> Result<String, CollectorError> {
    let data: IdentityResponse = serde_json::from_str(body)
        .map_err(|_| failure("ASUS identity response was missing, expired or malformed."))?;
    let version = if data.swpjverno.is_empty() {
        format!(
            "{}.{}_{}",
            data.firmver.replace('.', ""),
            data.buildno,
            data.extendno
        )
    } else {
        format!("{}_{}", data.swpjverno, data.extendno)
    };
    if !matches!(data.productid.as_str(), "RT-AX82U" | "RT-AX82U_V2")
        || version != asus::REVIEWED_BUILD
        || data.sw_mode != "1"
    {
        return Err(CollectorError::Unsupported("The authenticated response does not identify a reviewed RT-AX82U GNUton 3004.388.9_2-gnuton1 build in router mode. Settings were not read.".into()));
    }
    Ok(data.productid)
}

fn collect_with(
    target: &RouterTarget,
    ctx: &ProbeContext,
    options: &LoginOptions,
    transport: &mut impl Transport,
) -> Result<RouterFacts, CollectorError> {
    options.validate()?;
    ctx.check()?;
    let combined = Zeroizing::new(format!("{}:{}", options.username, options.password));
    let authorization =
        Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(combined.as_bytes()));
    let reply = transport.exchange(Endpoint::Login, Some(&authorization), None)?;
    let cookie = reply.cookie.filter(|_| reply.status == 200)
        .ok_or_else(|| failure("ASUS login was not accepted. It may require CAPTCHA, password setup, or a lockout wait. No automatic retry was attempted."))?;
    let result = (|| {
        ctx.check()?;
        let identity = transport.exchange(Endpoint::Identity, None, Some(&cookie))?;
        if identity.status != 200 {
            return Err(failure("ASUS identity read was rejected."));
        }
        let model = reviewed_identity(&identity.body)?;
        ctx.check()?;
        let settings = transport.exchange(Endpoint::Settings, None, Some(&cookie))?;
        if settings.status != 200 {
            return Err(failure("ASUS settings read was rejected."));
        }
        let mut facts = super::initial_facts(target);
        facts.settings = asus::decode_firewall_response(asus::REVIEWED_BUILD, &settings.body)?;
        ctx.check()?;
        match collect_wireless(ctx, transport, &cookie) {
            Ok(wireless) => {
                facts.settings.wifi_profiles = wireless.wifi_profiles;
                facts.settings.wifi_inventory_complete = wireless.wifi_inventory_complete;
            }
            Err(_) => {
                facts.settings.wifi_profiles = Known::Unavailable(
                    "Wireless settings read did not complete; firewall evidence remains available."
                        .into(),
                )
            }
        }
        facts.manufacturer = Some("ASUS".into());
        facts.model = Some(model.clone());
        facts.firmware = Some(asus::REVIEWED_BUILD.into());
        facts.firmware_assessment = super::intelligence::assess(
            &model,
            asus::REVIEWED_BUILD,
            options.support_region,
            chrono::Utc::now(),
        );
        facts.identity = Some(RouterIdentity { vendor: Known::Known("ASUS".into()), reported_model: Known::Known(model),
            firmware_version: Known::Known(asus::REVIEWED_BUILD.into()), authenticated_settings: Known::Known(true),
            evidence: vec!["Identity and firewall/WAN management settings reported by the authenticated HTTPS endpoint. Hardware compatibility has not been tested.".into()] });
        facts.requires_router_login.clear();
        facts.cannot_determine.push("Wireless inventory covers this router's declared local interfaces, not AiMesh nodes. Password strength and negotiated client encryption were not tested.".into());
        facts.evidence.push("One login, allowlisted reads with before/after wireless inventory checks, and best-effort logout; no configuration apply, reboot, wireless-control or firmware-upload endpoints.".into());
        Ok(facts)
    })();
    // Cancellation takes priority over session cleanup: never send another request
    // after a context switch. The router may retain its session until expiry.
    let logged_out = ctx.check().is_ok()
        && transport
            .exchange(Endpoint::Logout, None, Some(&cookie))
            .is_ok_and(|reply| reply.status == 200);
    result.map(|mut facts| {
        if !logged_out { facts.evidence.push("Logout could not be confirmed; the router session may remain until its own expiry. Local credentials and token were discarded.".into()); }
        facts
    })
}

fn collect_wireless(
    ctx: &ProbeContext,
    transport: &mut impl Transport,
    cookie: &str,
) -> Result<super::settings::RouterSettings, CollectorError> {
    use super::asus_wireless::{Inventory, Readings};
    ctx.check()?;
    let reply = transport.exchange(Endpoint::WirelessInventory, None, Some(cookie))?;
    if reply.status != 200 {
        return Err(failure("Wireless inventory read was rejected."));
    }
    let inventory = Inventory::parse(asus::REVIEWED_BUILD, &reply.body)?;
    let mut readings = Readings::new();
    for batch in inventory.batches() {
        if ctx.check().is_err() {
            readings.incomplete();
            break;
        }
        let reply = transport.exchange(Endpoint::WirelessBatch(batch.clone()), None, Some(cookie));
        match reply {
            Ok(reply) if reply.status == 200 => {
                readings.add(&batch, &reply.body)?;
            }
            _ => {
                readings.incomplete();
                break;
            }
        }
    }
    let unchanged = if ctx.check().is_ok() {
        transport
            .exchange(Endpoint::WirelessInventory, None, Some(cookie))
            .ok()
            .filter(|reply| reply.status == 200)
            .and_then(|reply| Inventory::parse(asus::REVIEWED_BUILD, &reply.body).ok())
            .is_some_and(|last| last == inventory)
    } else {
        false
    };
    Ok(readings.finish(&inventory, unchanged))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        replies: std::collections::VecDeque<Reply>,
        paths: Vec<String>,
    }
    impl Transport for Fake {
        fn exchange(
            &mut self,
            endpoint: Endpoint,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<Reply, CollectorError> {
            self.paths.push(endpoint.path().to_owned());
            self.replies
                .pop_front()
                .ok_or_else(|| failure("fixture exhausted"))
        }
    }
    fn reply(body: &str, login: bool) -> Reply {
        Reply {
            status: 200,
            body: Zeroizing::new(body.into()),
            cookie: login.then(|| Zeroizing::new("asus_token=abcdefghijklmnop".into())),
        }
    }
    fn options() -> LoginOptions {
        LoginOptions {
            username: "admin".into(),
            password: "synthetic-secret".into(),
            https_port: 8443,
            certificate_pem: String::new(),
            support_region: Default::default(),
        }
    }
    const ID: &str = r#"{"productid":"RT-AX82U","firmver":"3.0.0.4","buildno":"388.9","extendno":"2-gnuton1","sw_mode":"1"}"#;
    const INVENTORY: &str =
        r#"{"wl_ifnames":"eth5 eth6","wl0_vifnames":"wl0.4","wl1_vifnames":""}"#;
    #[test]
    fn authenticated_settings_flow_to_rules_without_secrets() {
        let target =
            super::super::target::candidates(&super::super::target::fixture(), 1).remove(0);
        let ctx = ProbeContext::new(&target);
        let mut fake = Fake {
            paths: vec![],
            replies: [
                reply("", true),
                reply(ID, false),
                reply(
                    r#"{"fw_enable_x":"0","ipv6_fw_enable":"1","misc_http_x":"1"}"#,
                    false,
                ),
                reply(INVENTORY, false),
                reply(r#"{"wps_enable":"0","wl0_radio":"1","wl1_radio":"0","wl0_bss_enabled":"1","wl0_auth_mode_x":"psk2","wl0.4_bss_enabled":"1","wl0.4_auth_mode_x":"open","wl0.4_wep_x":"0"}"#, false),
                reply(INVENTORY, false),
                reply("", false),
            ]
            .into(),
        };
        let facts = collect_with(&target, &ctx, &options(), &mut fake).unwrap();
        let rules = crate::rules::router::evaluate(&facts);
        assert!(rules.iter().any(|r| r.rule_id == "RTR-007"));
        assert!(rules.iter().any(|r| r.rule_id == "RTR-008"));
        assert!(rules.iter().any(|r| r.rule_id == "RTR-009"));
        assert!(matches!(
            facts.settings.wifi_inventory_complete,
            Known::Known(true)
        ));
        let stored = serde_json::to_string(&facts).unwrap();
        assert!(!stored.contains("synthetic-secret"));
        assert!(!stored.contains("abcdefghijklmnop"));
        assert_eq!(fake.paths.len(), 7);
        assert_eq!(fake.paths[0], "/login.cgi");
        assert_eq!(fake.paths[3], super::super::asus_wireless::INVENTORY_PATH);
        assert!(fake.paths[4].contains("wl0.4_auth_mode_x"));
        assert_eq!(fake.paths[5], super::super::asus_wireless::INVENTORY_PATH);
        assert_eq!(fake.paths[6], "/Logout.asp");
        assert_eq!(ctx.request_count(), 0);
    }
    #[test]
    fn changed_inventory_never_claims_complete_and_cancellation_stops_followups() {
        let target =
            super::super::target::candidates(&super::super::target::fixture(), 1).remove(0);
        let ctx = ProbeContext::new(&target);
        let mut fake = Fake {
            paths: vec![],
            replies: [
                reply(INVENTORY, false),
                reply("{}", false),
                reply(&INVENTORY.replace("wl0.4", "wl0.5"), false),
            ]
            .into(),
        };
        let settings = collect_wireless(&ctx, &mut fake, "asus_token=abcdefghijklmnop").unwrap();
        assert!(matches!(
            settings.wifi_inventory_complete,
            Known::Known(false)
        ));
        struct CancelAfterLogin<'a> {
            ctx: &'a ProbeContext,
            calls: usize,
        }
        impl Transport for CancelAfterLogin<'_> {
            fn exchange(
                &mut self,
                endpoint: Endpoint,
                _: Option<&str>,
                _: Option<&str>,
            ) -> Result<Reply, CollectorError> {
                self.calls += 1;
                assert!(matches!(endpoint, Endpoint::Login));
                self.ctx.cancel();
                Ok(reply("", true))
            }
        }
        let mut cancelled = CancelAfterLogin {
            ctx: &ctx,
            calls: 0,
        };
        assert!(collect_with(&target, &ctx, &options(), &mut cancelled).is_err());
        assert_eq!(
            cancelled.calls, 1,
            "no settings read or logout after cancellation"
        );
    }

    #[test]
    fn failed_login_is_not_retried_and_wrong_build_never_reads_settings() {
        let target =
            super::super::target::candidates(&super::super::target::fixture(), 1).remove(0);
        let ctx = ProbeContext::new(&target);
        let mut fake = Fake {
            paths: vec![],
            replies: [reply("CAPTCHA", false)].into(),
        };
        assert!(collect_with(&target, &ctx, &options(), &mut fake).is_err());
        assert_eq!(fake.paths.len(), 1);
        let mut fake = Fake {
            paths: vec![],
            replies: [
                reply("", true),
                reply(&ID.replace("2-gnuton1", "2"), false),
                reply("", false),
            ]
            .into(),
        };
        assert!(collect_with(&target, &ctx, &options(), &mut fake).is_err());
        assert_eq!(fake.paths, ["/login.cgi", IDENTITY, "/Logout.asp"]);
    }
    #[test]
    fn cancellation_and_bad_input_do_not_call_transport() {
        let target =
            super::super::target::candidates(&super::super::target::fixture(), 1).remove(0);
        let ctx = ProbeContext::new(&target);
        ctx.cancel();
        let mut fake = Fake {
            paths: vec![],
            replies: [].into(),
        };
        assert!(collect_with(&target, &ctx, &options(), &mut fake).is_err());
        assert!(fake.paths.is_empty());
        let mut input = options();
        input.username = "a:b".into();
        assert!(input.validate().is_err());
        input = options();
        input.certificate_pem = "PRIVATE KEY".into();
        assert!(input.validate().is_err());
        for cookie in [
            "asus_token=",
            "asus_token=abcdefghijklmnop\r\n",
            "other=abcdefghijklmnop",
            "asus_token=abcdefghijklmnop xyz",
        ] {
            assert!(parse_cookie(cookie).is_none());
        }
    }
}
