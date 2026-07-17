//! The SOCKS5 destination.

use std::net::SocketAddr;

/// A CONNECT destination: either a name (kept unresolved — the whole point of DNS-leak-free
/// proxying) or a literal socket address.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Target {
    /// A host name and port. `.fanos` names resolve in-network; others go to an exit.
    Name(String, u16),
    /// A literal IP socket address.
    Ip(SocketAddr),
}

impl Target {
    /// The destination port.
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::Name(_, p) => *p,
            Self::Ip(a) => a.port(),
        }
    }

    /// Whether this is a `.fanos` name (case-insensitive) — handled in-network, never via DNS.
    #[must_use]
    pub fn is_fanos(&self) -> bool {
        match self {
            Self::Name(host, _) => {
                let lower = host.to_ascii_lowercase();
                lower.strip_suffix(".fanos").is_some()
            }
            Self::Ip(_) => false,
        }
    }

    /// The host part as a string (a name, or the IP rendered).
    #[must_use]
    pub fn host(&self) -> String {
        match self {
            Self::Name(host, _) => host.clone(),
            Self::Ip(a) => a.ip().to_string(),
        }
    }
}

impl core::fmt::Display for Target {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Name(host, port) => write!(f, "{host}:{port}"),
            Self::Ip(a) => write!(f, "{a}"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn classifies_fanos_names() {
        assert!(Target::Name("Blog.Alice.FANOS".into(), 80).is_fanos());
        assert!(Target::Name("service.fanos".into(), 443).is_fanos());
        assert!(!Target::Name("example.com".into(), 80).is_fanos());
        assert!(!Target::Ip("1.2.3.4:80".parse().unwrap()).is_fanos());
        // A name merely containing "fanos" is not a .fanos TLD.
        assert!(!Target::Name("fanos.example.com".into(), 80).is_fanos());
    }

    #[test]
    fn reports_port_and_host() {
        assert_eq!(Target::Name("x.fanos".into(), 8080).port(), 8080);
        assert_eq!(Target::Ip("9.9.9.9:53".parse().unwrap()).port(), 53);
        assert_eq!(Target::Name("x.fanos".into(), 1).host(), "x.fanos");
    }
}
