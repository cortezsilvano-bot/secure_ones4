//! Bounded, cancellable local requests shared by every router provider.
use super::{AdminPort, AdminProtocol, EncryptionState};
use crate::security::CollectorError;
use crate::security::Known;
use parking_lot::Mutex;
use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub const MAX_BODY_BYTES: u64 = 256 * 1024;
pub const MAX_REQUESTS: usize = 208; // discovery + description + 200 mappings + six TCP probes
pub const SCAN_DEADLINE: Duration = Duration::from_secs(20);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct ProbeContext {
    pub(crate) address: Ipv4Addr,
    pub(crate) local_address: Ipv4Addr,
    cancelled: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    deadline: Instant,
    limit: usize,
    observed_services: Arc<Mutex<Vec<AdminPort>>>,
}

impl ProbeContext {
    pub fn new(target: &super::target::RouterTarget) -> Self {
        Self {
            address: target.address,
            local_address: target.local_address,
            cancelled: Arc::new(AtomicBool::new(false)),
            requests: Arc::new(AtomicUsize::new(0)),
            deadline: Instant::now() + SCAN_DEADLINE,
            limit: MAX_REQUESTS,
            observed_services: Arc::new(Mutex::new(Vec::new())),
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
    pub fn check(&self) -> Result<(), CollectorError> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(CollectorError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(CollectorError::Timeout(SCAN_DEADLINE.as_secs()));
        }
        Ok(())
    }
    pub fn reserve(&self) -> Result<Duration, CollectorError> {
        self.check()?;
        // Unit tests may use loopback fixtures, but can never target the real LAN.
        if cfg!(test) && !self.address.is_loopback() {
            return Err(CollectorError::Unsupported(
                "Live router requests are disabled in unit-test builds.".into(),
            ));
        }
        self.requests
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.limit).then_some(n + 1)
            })
            .map_err(|_| {
                CollectorError::Unavailable(
                    "Router request budget exhausted; remaining checks did not run.".into(),
                )
            })?;
        self.remaining()
    }
    pub fn remaining(&self) -> Result<Duration, CollectorError> {
        self.check()?;
        Ok(self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(REQUEST_TIMEOUT)
            .max(Duration::from_millis(1)))
    }
    pub fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    pub fn observed_services(&self) -> Vec<AdminPort> {
        self.observed_services.lock().clone()
    }

    #[cfg(test)]
    pub(crate) fn fixture_http_response(&self, url: &str) -> Result<(), CollectorError> {
        self.record_http_response(url)
    }

    /// Call only after a successful response on this context's HTTP client.
    /// Scheme alone is not evidence: the caller must have completed the request
    /// with redirects disabled and normal TLS verification still enabled.
    pub(super) fn record_http_response(&self, url: &str) -> Result<(), CollectorError> {
        self.validate_url(url)?;
        self.check()?;
        let uri: ureq::http::Uri = url
            .parse()
            .map_err(|_| CollectorError::Unavailable("Invalid observed endpoint.".into()))?;
        let tls = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let mut service = AdminPort::tcp_open(port);
        service.service_hint = None;
        service.protocol = Known::Known(if tls {
            AdminProtocol::Https
        } else {
            AdminProtocol::Http
        });
        service.encryption = Known::Known(if tls {
            EncryptionState::Encrypted
        } else {
            EncryptionState::Plaintext
        });
        let mut observed = self.observed_services.lock();
        // A port can answer both plaintext and TLS. Preserve distinct transports.
        if !observed.iter().any(|previous| {
            previous.port == port
                && matches!(
                    (&previous.protocol, &service.protocol),
                    (
                        Known::Known(AdminProtocol::Http),
                        Known::Known(AdminProtocol::Http)
                    ) | (
                        Known::Known(AdminProtocol::Https),
                        Known::Known(AdminProtocol::Https)
                    )
                )
        }) {
            observed.push(service);
        }
        Ok(())
    }

    pub fn validate_url(&self, url: &str) -> Result<(), CollectorError> {
        let denied = || {
            CollectorError::Unavailable(
                "Router supplied a destination outside the selected gateway policy.".into(),
            )
        };
        if url.len() > 2048 || url.chars().any(|c| c.is_control()) || url.contains(['\\', '#']) {
            return Err(denied());
        }
        let uri: ureq::http::Uri = url.parse().map_err(|_| denied())?;
        if !matches!(uri.scheme_str(), Some("http" | "https")) {
            return Err(denied());
        }
        let authority = uri.authority().ok_or_else(denied)?;
        if authority.as_str().contains('@') || authority.port_u16() == Some(0) {
            return Err(denied());
        }
        // Literal IP only: no DNS aliases, rebinding, alternate IP encodings or credentials.
        if authority.host().parse::<Ipv4Addr>().ok() != Some(self.address) {
            return Err(denied());
        }
        Ok(())
    }

    pub fn http(
        &self,
        url: &str,
        soap: Option<(&str, &str)>,
    ) -> Result<(u16, String), CollectorError> {
        self.validate_url(url)?;
        let timeout = self.reserve()?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .build()
            .into();
        let response = match soap {
            Some((action, body)) => agent
                .post(url)
                .header("Content-Type", "text/xml; charset=\"utf-8\"")
                .header("SOAPAction", action)
                .send(body),
            None => agent.get(url).call(),
        };
        self.check()?;
        let mut response = response
            .map_err(|e| CollectorError::Unavailable(format!("Router request failed: {e}")))?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err(CollectorError::Unavailable(
                "Router redirects are not followed.".into(),
            ));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY_BYTES)
            .read_to_string()
            .map_err(|e| {
                CollectorError::Unavailable(format!(
                    "Router response was incomplete or too large: {e}"
                ))
            })?;
        self.check()?;
        self.record_http_response(url)?;
        Ok((status, body))
    }
}

#[cfg(test)]
pub(crate) fn fixture(address: Ipv4Addr) -> ProbeContext {
    let mut target = super::target::candidates(&super::target::fixture(), 1).remove(0);
    target.address = address;
    ProbeContext::new(&target)
}

#[cfg(test)]
mod offline_observation_tests {
    use super::*;

    #[test]
    fn observations_are_shared_deduplicated_and_do_not_consume_requests() {
        let ctx = fixture("192.168.1.1".parse().unwrap());
        let sibling = ctx.clone();
        ctx.fixture_http_response("http://192.168.1.1:49000/root.xml")
            .unwrap();
        sibling
            .fixture_http_response("http://192.168.1.1:49000/control?secret=value")
            .unwrap();
        sibling
            .fixture_http_response("https://192.168.1.1:49000/control")
            .unwrap();
        let observed = ctx.observed_services();
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0].port, 49000);
        assert!(matches!(
            observed[0].protocol,
            Known::Known(AdminProtocol::Http)
        ));
        assert!(matches!(
            observed[1].protocol,
            Known::Known(AdminProtocol::Https)
        ));
        assert_eq!(ctx.request_count(), 0);
        let json = serde_json::to_string(&observed).unwrap();
        assert!(!json.contains("secret"));
        assert!(!json.contains("control"));
    }

    #[test]
    fn foreign_or_cancelled_observations_are_rejected() {
        let ctx = fixture("192.168.1.1".parse().unwrap());
        assert!(ctx
            .fixture_http_response("http://192.168.1.2/root.xml")
            .is_err());
        ctx.cancel();
        assert!(ctx
            .fixture_http_response("http://192.168.1.1/root.xml")
            .is_err());
        assert!(ctx.observed_services().is_empty());
        assert_eq!(ctx.request_count(), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let url = format!("http://{}/description", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let task = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("mock server: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.extend(byte);
                assert!(request.len() < 8192);
            }
            let _ = stream.write_all(&response);
        });
        (url, task)
    }

    #[test]
    fn redirects_are_rejected_without_contacting_the_destination() {
        let destination = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        destination.set_nonblocking(true).unwrap();
        let response = format!("HTTP/1.1 302 Found\r\nLocation: http://{}/escape\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", destination.local_addr().unwrap());
        let (url, task) = server(response.into_bytes());
        assert!(fixture(Ipv4Addr::LOCALHOST).http(&url, None).is_err());
        task.join().unwrap();
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn oversized_and_truncated_responses_cannot_become_facts() {
        for response in [
            [
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    MAX_BODY_BYTES + 1
                )
                .into_bytes(),
                vec![b'x'; MAX_BODY_BYTES as usize + 1],
            ]
            .concat(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec(),
        ] {
            let (url, task) = server(response);
            assert!(fixture(Ipv4Addr::LOCALHOST).http(&url, None).is_err());
            task.join().unwrap();
        }
    }

    #[test]
    fn cancellation_before_http_sends_no_request() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let ctx = fixture(Ipv4Addr::LOCALHOST);
        ctx.cancel();
        assert!(matches!(
            ctx.http(&format!("http://{}/", listener.local_addr().unwrap()), None),
            Err(CollectorError::Cancelled)
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(ctx.request_count(), 0);
    }
    #[test]
    fn only_exact_gateway_http_destinations_are_allowed() {
        let ctx = fixture("192.168.1.1".parse().unwrap());
        for allowed in [
            "http://192.168.1.1:49000/root.xml",
            "https://192.168.1.1/control?x=1",
        ] {
            assert!(ctx.validate_url(allowed).is_ok());
        }
        for denied in [
            "http://8.8.8.8/",
            "http://192.168.1.2/",
            "http://router.asus.com/",
            "http://127.0.0.1/",
            "http://192.168.1.1@8.8.8.8/",
            "http://u:p@192.168.1.1/",
            "file://192.168.1.1/",
            "http://3232235777/",
            "http://192.168.1.1:0/",
            "http://192.168.1.1/#x",
            "http://192.168.1.1/\r\nX: y",
        ] {
            assert!(ctx.validate_url(denied).is_err(), "{denied}");
        }
    }
    #[test]
    fn cancellation_deadlines_and_shared_budgets_prevent_more_requests() {
        let mut ctx = fixture(Ipv4Addr::LOCALHOST);
        ctx.limit = 1;
        ctx.reserve().unwrap();
        assert!(ctx.clone().reserve().is_err());
        ctx.cancel();
        assert!(matches!(ctx.check(), Err(CollectorError::Cancelled)));
        let mut ctx = fixture("192.168.1.1".parse().unwrap());
        ctx.deadline = Instant::now();
        assert!(matches!(ctx.reserve(), Err(CollectorError::Timeout(_))));
    }

    #[test]
    fn real_router_requests_are_rejected_before_any_socket_can_be_opened() {
        let ctx = fixture("192.168.1.1".parse().unwrap());
        assert!(matches!(ctx.reserve(), Err(CollectorError::Unsupported(_))));
        assert_eq!(ctx.request_count(), 0);
    }
}
