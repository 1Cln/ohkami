mod basicauth;
pub use basicauth::BasicAuth;

mod cors;
pub use cors::Cors;

mod csrf;
pub use csrf::Csrf;

mod jwt;
pub use jwt::{Jwt, JwtToken};

mod context;
pub use context::Context;

pub mod enamel;
pub use enamel::Enamel;

#[cfg(feature = "__rt_native__")]
mod timeout;
#[cfg(feature = "__rt_native__")]
pub use timeout::Timeout;

/* #660 will replace this with an original struct
   (providing almost the same interface as this using original implementations internally)
*/
// Just wrapping `https::uri::Uri` for now to skip most difficult things in parsing,
// so we only have to handle HTTP-origin-specific rules on the top of the generic `Uri`.
#[derive(Clone, Debug)]
pub struct Origin(http::uri::Uri);

#[derive(Debug)]
pub enum OriginError {
    InvalidUri(http::uri::InvalidUri),
    FaultyScheme,
    FaultyUriLength,
    FaultyUriPartLength,
    FaultyPort,
    FaultyIp,
    MalformedUri
}

#[derive(PartialEq)]
pub enum Scheme {
    Http,
    Https
}

impl Origin {
    /// Parse string into HTTP origin.
    ///
    /// # Examples
    /// ```rust
    /// fn run() {
    ///     Origin::new("https://localhost:3000").unwrap();
    /// }
    /// ```
    /// # Errors
    ///
    /// This function will return an error if the given URI string fails the validation included in this function.
    /// Rules include:
    ///
    /// - Generalistic http::uri::Uri rules for URI's.
    /// - Scheme must be either HTTP or HTTPS.
    /// - URI length mustn't exceed 255 characters in total.
    /// - URI parts mustn't exceed 63 characters per.
    /// - Ports must be numeric and <= 65535 (u16::MAX).
    /// - IP strings like 192.168.1.0 cannot have wildcards.
    ///
    fn new(s: &str) -> Result<Self, OriginError> {
        use http::uri::{Uri, Scheme};

        let uri = s.parse::<Uri>()
            .map_err(OriginError::InvalidUri)?;

        // Additional validation
        // Validate scheme is HTTP or HTTPS
        if let Some(scheme) = uri.scheme() && scheme != &Scheme::HTTP && scheme != &Scheme::HTTPS {
            return Err(OriginError::FaultyScheme);
        }

        if let Some(host) = uri.host() {
            // Validate max host length
            if host.chars().count() > 253 {
                return Err(OriginError::FaultyUriLength)
            }

            if host.contains("..") {
                return Err(OriginError::MalformedUri)
            }

            let split_host: Vec<&str> = host.split('.').collect();

            // Validate max part length
            if !split_host.iter().all(|part| part.chars().count() <= 63) {
                return Err(OriginError::FaultyUriPartLength)
            }

            if split_host.len() < 4 && host.chars().all(|c| c.is_numeric() || c == '.') {
                return Err(OriginError::FaultyIp)
            }
        }

        // Check if user intended to add a port to Origin, but it's parsed out by http::uri::Uri, return invalid port error
        if let Some((_, rest)) = s.split_once(':') && rest.contains(':') && uri.port_u16().is_none() {
            return Err(OriginError::FaultyPort)
        }

        Ok(Self(uri))
    }

    fn scheme(&self) -> Scheme {
        if self.0.scheme() == Some(&http::uri::Scheme::HTTP) {
            Scheme::Http
        } else {
            Scheme::Https // definitely Https because of `Self::new` parser logic
        }
    }

    fn port(&self) -> Option<u16> {
        self.0.port_u16()
    }

    fn host(&self) -> Option<&str> {
        self.0.host()
    }

}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for OriginError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // `http::uri::InvalidUri` doesn't implement `PartialEq`
            (Self::InvalidUri(a), Self::InvalidUri(b)) =>
                a.to_string() == b.to_string(),
            | (Self::FaultyScheme, Self::FaultyScheme)
            | (Self::FaultyUriLength, Self::FaultyUriLength)
            | (Self::FaultyUriPartLength, Self::FaultyUriPartLength)
            | (Self::FaultyPort, Self::FaultyPort)
            | (Self::FaultyIp, Self::FaultyIp)
            | (Self::MalformedUri, Self::MalformedUri)
            => true,
            _ => false
        }
    }
}

impl std::fmt::Display for OriginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = match self {
            OriginError::InvalidUri(_) => { "Invalid URI." }
            OriginError::FaultyScheme => { "Please use HTTP or HTTPS as scheme." }
            OriginError::FaultyUriLength => { "URI length mustn't exceed 253 characters in total." }
            OriginError::FaultyUriPartLength => { "URI part length mustn't exceed 63 characters." }
            OriginError::FaultyPort => { "Port number was expected." }
            OriginError::FaultyIp => { "Ip was misformatted." }
            OriginError::MalformedUri => { "URI is malformed." }
        };

        write!(f, "{}", output)
    }
}

#[cfg(test)]
mod test {
    use super::{Origin, OriginError};

    #[test]
    fn origin_invalid_origin_ip_invalidation() {
        assert_eq!(
            &Origin::new("https://192.168.a.58:8080").unwrap_err(),
            &OriginError::FaultyIp
        )
    }

    #[test]
    fn origin_wildcard_in_extension_invalidation() {
        assert_eq!(
            &Origin::new("https://test.example.*:8080").unwrap_err(),
            &OriginError::MalformedUri
        )
    }

    #[test]
    fn origin_wildcard_in_sld_invalidation() {
        assert_eq!(
            &Origin::new("https://test.*.com:8080").unwrap_err(),
            &OriginError::MalformedUri
        )
    }

    #[test]
    fn origin_faulty_wildcard_in_ip_invalidation() {
        assert_eq!(
            &Origin::new("https://192.*.1.15:8080").unwrap_err(),
            &OriginError::FaultyIp
        );

        assert_eq!(
            &Origin::new("https://*.168.1.15:8080").unwrap_err(),
            &OriginError::FaultyIp
        )
    }

    #[test]
    fn origin_scheme_invalidation() {
        assert_eq!(OriginError::FaultyScheme, Origin::new("foobarhttp://example.com").unwrap_err())
    }

    #[test]
    fn origin_length_invalidation() {
        let origin = "https://thisisaridiculouslylongurithatshoulddefinitelybeinvalidaccordingtothistest.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl.com";
        assert_eq!(Origin::new(origin).unwrap_err(), OriginError::FaultyUriLength)
    }

    #[test]
    fn origin_part_length_invalidation() {
        let origin = "https://www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnoqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com";
        assert_eq!(Origin::new(origin).unwrap_err(), OriginError::FaultyUriPartLength)
    }

    #[test]
    fn origin_port_invalidation() {
        assert_eq!(Origin::new("http://example.com:abcd").unwrap_err(), OriginError::FaultyPort)
    }

    #[test]
    fn origin_invalid_ip_port_range_invalidation() {
        // Origin:new with a faulty IP should give OriginError::FaultyPort.
        // This error cannot be compared with super::CorsOriginValue::matches(), due to it being an error.
        assert_eq!(
            Origin::new("https://192.168.1.0:80080").unwrap_err(),
            OriginError::FaultyPort
        )
    }

    #[test]
    fn origin_host_invalidation() {
        assert!(
            Origin::new("http://%example.com").is_err() //Gives InvalidUri error, which's enums aren't public so unable to directly compare.
        )
    }

    #[test]
    fn origin_malformed_uri_invalidation() {
        assert_eq!(
            &OriginError::MalformedUri,
            &Origin::new("https://a..example.com").unwrap_err()
        );

        assert_eq!(
            &OriginError::MalformedUri,
            &Origin::new("https://..example.com").unwrap_err()
        );
    }
}