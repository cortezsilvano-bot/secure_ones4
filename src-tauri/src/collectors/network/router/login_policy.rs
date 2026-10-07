//! Offline policy foundation only: no credentials, session tokens, or I/O.
//! Alternative fingerprint policy; runtime uses scan-scoped verified TLS roots.
//! A fingerprint-based provider must validate the
//! live connection, recheck cancellation/generation, and consume this gate just
//! before sending credentials on that same connection. Never retry automatically.
use std::time::Instant;

use super::target::RouterTarget;

/// Backend-observed certificate digest from a completed TLS handshake. Do not
/// deserialize trust evidence from IPC or infer it from a port or URL.
pub enum ConnectionTrust {
    VerifiedTls { certificate_sha256: [u8; 32] },
    Plaintext,
    Unverified,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoginDenied {
    ApprovalRequired,
    ProviderUnsupported,
    InvalidPort,
    TrustedTlsRequired,
    Expired,
    Cancelled,
    TargetChanged,
    CertificateChanged,
    AlreadyConsumed,
}

/// Intentionally neither Clone nor Serialize: ephemeral, single-attempt approval.
/// It contains no password, cookie, or login response.
pub struct LoginApproval {
    target: RouterTarget,
    port: u16,
    certificate_sha256: [u8; 32],
    expires_at: Instant,
    consumed: bool,
}

impl LoginApproval {
    /// `provider_supported` must come from a backend allowlist of validated
    /// read-only firmware adapters, never from self-reported ASUS identification.
    /// This component is isolated; the ASUS runtime uses a separate TLS-root policy.
    pub fn issue(
        target: &RouterTarget,
        port: u16,
        trust: ConnectionTrust,
        confirmed: bool,
        provider_supported: bool,
        expires_at: Instant,
    ) -> Result<Self, LoginDenied> {
        if !confirmed {
            return Err(LoginDenied::ApprovalRequired);
        }
        if !provider_supported {
            return Err(LoginDenied::ProviderUnsupported);
        }
        if port == 0 {
            return Err(LoginDenied::InvalidPort);
        }
        let ConnectionTrust::VerifiedTls { certificate_sha256 } = trust else {
            return Err(LoginDenied::TrustedTlsRequired);
        };
        if expires_at <= Instant::now() {
            return Err(LoginDenied::Expired);
        }
        Ok(Self {
            target: target.clone(),
            port,
            certificate_sha256,
            expires_at,
            consumed: false,
        })
    }

    /// Every attempt consumes approval, including a rejected attempt. A timeout,
    /// failed password, lockout response, or unexpected reply must not reuse it.
    pub fn consume(
        &mut self,
        target: &RouterTarget,
        port: u16,
        trust: ConnectionTrust,
        cancelled: bool,
    ) -> Result<(), LoginDenied> {
        if self.consumed {
            return Err(LoginDenied::AlreadyConsumed);
        }
        self.consumed = true;
        if cancelled {
            return Err(LoginDenied::Cancelled);
        }
        if Instant::now() >= self.expires_at {
            return Err(LoginDenied::Expired);
        }
        if target != &self.target || port != self.port {
            return Err(LoginDenied::TargetChanged);
        }
        let ConnectionTrust::VerifiedTls { certificate_sha256 } = trust else {
            return Err(LoginDenied::TrustedTlsRequired);
        };
        if certificate_sha256 != self.certificate_sha256 {
            return Err(LoginDenied::CertificateChanged);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::target;
    use super::*;
    use std::time::Duration;

    fn router() -> RouterTarget {
        target::candidates(&target::fixture(), 1).remove(0)
    }
    fn trusted() -> ConnectionTrust {
        ConnectionTrust::VerifiedTls {
            certificate_sha256: [7; 32],
        }
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }
    fn approval() -> LoginApproval {
        LoginApproval::issue(&router(), 8443, trusted(), true, true, deadline()).unwrap()
    }

    #[test]
    fn requires_explicit_approval_and_supported_provider() {
        assert!(matches!(
            LoginApproval::issue(&router(), 8443, trusted(), false, true, deadline()),
            Err(LoginDenied::ApprovalRequired)
        ));
        assert!(matches!(
            LoginApproval::issue(&router(), 8443, trusted(), true, false, deadline()),
            Err(LoginDenied::ProviderUnsupported)
        ));
        assert!(matches!(
            LoginApproval::issue(&router(), 0, trusted(), true, true, deadline()),
            Err(LoginDenied::InvalidPort)
        ));
    }

    #[test]
    fn rejects_untrusted_transport_at_both_stages() {
        for trust in [ConnectionTrust::Plaintext, ConnectionTrust::Unverified] {
            assert!(matches!(
                LoginApproval::issue(&router(), 443, trust, true, true, deadline()),
                Err(LoginDenied::TrustedTlsRequired)
            ));
        }
        assert_eq!(
            approval().consume(&router(), 8443, ConnectionTrust::Unverified, false),
            Err(LoginDenied::TrustedTlsRequired)
        );
    }

    #[test]
    fn exactly_one_attempt_even_after_failure() {
        let mut gate = approval();
        assert_eq!(gate.consume(&router(), 8443, trusted(), false), Ok(()));
        assert_eq!(
            gate.consume(&router(), 8443, trusted(), false),
            Err(LoginDenied::AlreadyConsumed)
        );
        let mut cancelled = approval();
        assert_eq!(
            cancelled.consume(&router(), 8443, trusted(), true),
            Err(LoginDenied::Cancelled)
        );
        assert_eq!(
            cancelled.consume(&router(), 8443, trusted(), false),
            Err(LoginDenied::AlreadyConsumed)
        );
    }

    #[test]
    fn router_generation_interface_address_and_port_are_bound() {
        for mutate in [
            (|t: &mut RouterTarget| t.network_generation += 1) as fn(&mut RouterTarget),
            |t| t.address = "192.168.1.2".parse().unwrap(),
            |t| t.interface_id.push_str("changed"),
            |t| t.local_address = "192.168.1.21".parse().unwrap(),
            |t| t.gateway_mac = Some("00:11:22:33:44:55".into()),
        ] {
            let mut changed = router();
            mutate(&mut changed);
            assert_eq!(
                approval().consume(&changed, 8443, trusted(), false),
                Err(LoginDenied::TargetChanged)
            );
        }
        assert_eq!(
            approval().consume(&router(), 443, trusted(), false),
            Err(LoginDenied::TargetChanged)
        );
    }

    #[test]
    fn certificate_change_requires_new_approval() {
        assert_eq!(
            approval().consume(
                &router(),
                8443,
                ConnectionTrust::VerifiedTls {
                    certificate_sha256: [8; 32]
                },
                false
            ),
            Err(LoginDenied::CertificateChanged)
        );
    }

    #[test]
    fn expiry_rejects_without_sleeping_or_io() {
        assert!(matches!(
            LoginApproval::issue(&router(), 8443, trusted(), true, true, Instant::now()),
            Err(LoginDenied::Expired)
        ));
        let mut gate = approval();
        gate.expires_at = Instant::now();
        assert_eq!(
            gate.consume(&router(), 8443, trusted(), false),
            Err(LoginDenied::Expired)
        );
    }
}
