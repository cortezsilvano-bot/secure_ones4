//! Conservative interpretation of bounded response bytes; performs no I/O.
//! Callers must associate bytes and transport evidence with the same endpoint
//! and scan generation. This parser neither establishes certificate trust nor
//! authorizes credentials, redirects, or another request.
use super::{AdminPort, AdminProtocol, EncryptionState};
use crate::security::Known;
use std::io::Read;

/// Read a bounded first-line greeting from an already established connection.
/// Does not write any data or start another connection. The caller supplies
/// deadline/cancellation handling before each read.
pub fn read_greeting(
    reader: &mut impl Read,
    port: u16,
    mut before_read: impl FnMut() -> bool,
) -> AdminPort {
    let mut bytes = Vec::with_capacity(255);
    while bytes.len() < 255 && before_read() {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(1) => bytes.push(byte[0]),
            _ => break,
        }
        if bytes.ends_with(b"\r\n") {
            break;
        }
    }
    interpret(port, &bytes, ObservedTransport::PlainTcp)
}

/// Supplied by a future transport collector, never inferred from port numbers
/// or from TLS-looking bytes. TLS means a completed handshake and decrypted data.
pub enum ObservedTransport {
    PlainTcp,
    EstablishedTls,
}

/// Interpret a small response prefix. Recognizes only a complete HTTP/1 status
/// line or an SSH-2.0 identification on the first line. Other forms stay unknown.
/// A banner establishes an advertised protocol, not a successful SSH session.
pub fn interpret(port: u16, response: &[u8], transport: ObservedTransport) -> AdminPort {
    let mut result = AdminPort::tcp_open(port);
    result.protocol = Known::Unavailable("No recognized complete protocol response.".into());
    result.encryption = match transport {
        ObservedTransport::EstablishedTls => Known::Known(EncryptionState::Encrypted),
        ObservedTransport::PlainTcp => Known::NotScanned,
    };
    // Do not retain response bodies, banners, cookies, or authentication headers.
    if response.len() > 4096 {
        return result;
    }
    let Some(end) = response.windows(2).position(|bytes| bytes == b"\r\n") else {
        return result;
    };
    let line = &response[..end];
    if line.iter().any(|byte| !matches!(byte, 0x20..=0x7e)) {
        return result;
    }
    let http = (line.starts_with(b"HTTP/1.0 ") || line.starts_with(b"HTTP/1.1 "))
        && line.len() >= 13
        && matches!(line[9], b'1'..=b'5')
        && line[10..12].iter().all(u8::is_ascii_digit)
        && line[12] == b' ';
    if http {
        let (protocol, encryption) = match transport {
            ObservedTransport::PlainTcp => (AdminProtocol::Http, EncryptionState::Plaintext),
            ObservedTransport::EstablishedTls => (AdminProtocol::Https, EncryptionState::Encrypted),
        };
        result.protocol = Known::Known(protocol);
        result.encryption = Known::Known(encryption);
    } else if matches!(transport, ObservedTransport::PlainTcp)
        && line.len() <= 253
        && line.starts_with(b"SSH-2.0-")
        && line[8..]
            .split(|byte| *byte == b' ')
            .next()
            .is_some_and(|software| {
                !software.is_empty()
                    && software
                        .iter()
                        .all(|byte| matches!(byte, 0x21..=0x7e) && *byte != b'-')
            })
    {
        result.protocol = Known::Known(AdminProtocol::Ssh);
        // Key exchange has not taken place; a banner does not prove encryption.
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_read_is_bounded_and_stops_at_first_line() {
        let mut input = std::io::Cursor::new(b"SSH-2.0-Fixture\r\nsecret-tail".to_vec());
        let result = read_greeting(&mut input, 22, || true);
        assert!(matches!(result.protocol, Known::Known(AdminProtocol::Ssh)));
        assert_eq!(input.position(), 17);
        let mut oversized = std::io::Cursor::new(vec![b'x'; 1000]);
        assert!(!read_greeting(&mut oversized, 22, || true)
            .protocol
            .is_known());
        assert_eq!(oversized.position(), 255);
    }

    #[test]
    fn cancelled_greeting_read_does_not_consume_input() {
        let mut input = std::io::Cursor::new(b"SSH-2.0-Fixture\r\n".to_vec());
        assert!(!read_greeting(&mut input, 22, || false).protocol.is_known());
        assert_eq!(input.position(), 0);
    }

    #[test]
    fn observed_http_overrides_conventional_port_hint() {
        let result = interpret(
            443,
            b"HTTP/1.1 401 Unauthorized\r\n",
            ObservedTransport::PlainTcp,
        );
        assert!(matches!(result.protocol, Known::Known(AdminProtocol::Http)));
        assert!(matches!(
            result.encryption,
            Known::Known(EncryptionState::Plaintext)
        ));
    }

    #[test]
    fn https_requires_transport_evidence() {
        let result = interpret(
            80,
            b"HTTP/1.0 302 Found\r\n",
            ObservedTransport::EstablishedTls,
        );
        assert!(matches!(
            result.protocol,
            Known::Known(AdminProtocol::Https)
        ));
        assert!(matches!(
            result.encryption,
            Known::Known(EncryptionState::Encrypted)
        ));
        let tls_only = interpret(443, b"unrecognized", ObservedTransport::EstablishedTls);
        assert!(!tls_only.protocol.is_known());
    }

    #[test]
    fn ssh_banner_does_not_prove_encrypted_session() {
        let result = interpret(
            2222,
            b"SSH-2.0-OpenSSH_9.0\r\n",
            ObservedTransport::PlainTcp,
        );
        assert!(matches!(result.protocol, Known::Known(AdminProtocol::Ssh)));
        assert!(!result.encryption.is_known());
    }

    #[test]
    fn malformed_truncated_and_unrecognized_responses_stay_unknown() {
        for bytes in [
            &b"HTTP/1.1 200 OK"[..],
            &b"HTTP/1.1 999 Invalid\r\n"[..],
            &b"HTTP/1.1 2000 OK\r\n"[..],
            &b"HTTP/1.1 200\0OK\r\n"[..],
            &b"SSH-2.0-\r\n"[..],
            &b"login: \r\n"[..],
            &b"\x16\x03\x03\r\n"[..],
        ] {
            let result = interpret(23, bytes, ObservedTransport::PlainTcp);
            assert!(!result.protocol.is_known(), "{bytes:?}");
            assert!(!result.encryption.is_known());
        }
    }

    #[test]
    fn bounded_input_and_serialization_do_not_retain_sensitive_responses() {
        let oversized = vec![b'x'; 4097];
        assert!(!interpret(80, &oversized, ObservedTransport::PlainTcp)
            .protocol
            .is_known());
        let result = interpret(
            80,
            b"HTTP/1.1 200 OK\r\nSet-Cookie: secret-token\r\n\r\nprivate-body",
            ObservedTransport::PlainTcp,
        );
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("secret-token"));
        assert!(!json.contains("private-body"));
    }
}
