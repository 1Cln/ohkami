mod basicauth;
use core::{fmt::Display, option::Option::Some};
use std::fmt::Formatter;
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

use http::uri::{InvalidUri, Uri};

#[cfg(feature = "__rt_native__")]
mod timeout;
#[cfg(feature = "__rt_native__")]
pub use timeout::Timeout;

/* #660 will replace this with an original struct
   (providing almost the same interface as this
   using original implementations internally)
*/
// Just wrapping `https::uri::Uri` for now
// to skip most difficult things in parsing,
// so we only have to handle HTTP-origin-specific rules
// on the top of the generic `Uri`.
#[derive(Clone, Debug)]
pub struct Origin(Uri);

#[derive(Debug)]
pub enum OriginError {
    InvalidUri(InvalidUri),
    FaultyScheme,
    FaultyUriLength,
    FaultyUriPartLength,
    FaultyPort,
    //...
}

pub enum Scheme {
    Http,
    Https
}

impl Origin {
    /* This replaces current `fn validate_origin` entirely */
    /// Parse string into HTTP origin
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
            if host.chars().count() > u8::MAX as usize {
                return Err(OriginError::FaultyUriLength)
            }

            // Validate max part length
            if !host.split('.').all(|part| part.chars().count() <= 63) {
                return Err(OriginError::FaultyUriPartLength)
            }
        }

        // Check if user intended to add a port to Origin, but it's parsed out by http::uri::Uri, return invalid port error
        if let Some((_, rest)) = s.split_once(':') && rest.contains(':') && uri.port_u16().is_none() {
            return Err(OriginError::FaultyPort)
        }

        // TODO: Add more if necessary

        Ok(Self(uri))
    }

    // Accessor methods for origin components; for example:
    #[allow(unused)]
    fn scheme(&self) -> Scheme {
        if self.0.scheme() == Some(&http::uri::Scheme::HTTP) {
            Scheme::Http
        } else {
            Scheme::Https // definitely Https because of `Self::new` parser logic
        }
        // #606 will remove such heuristic if-else and then
        // we just have to access `.scheme` field or something like that
    }

    fn port(&self) -> Option<u16> {
        self.0.port_u16()
    }

    #[allow(unused)]
    fn host(&self) -> Option<&str> {
        self.0.host()
    }

    fn host_as_subdomain_and_domain(&self) -> (Option<&str>, &str) {
        if let Some(host) = self.0.host() {
            host.split_once('.')
                .map_or((None, host), |(subdomain, domain)| {
                    if domain.contains('.') {
                        (Some(subdomain), domain)
                    } else {
                        (None, host)
                    }
                })
        } else {
            (None, "")
        }

    }

    // and more... (as needed)
}

impl Display for Origin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Display for OriginError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let output = match self {
            OriginError::InvalidUri(_) => { "Invalid URI." }
            OriginError::FaultyScheme => { "Please use HTTP or HTTPS as scheme." }
            OriginError::FaultyUriLength => { "URI length mustn't exceed 255 characters in total." }
            OriginError::FaultyUriPartLength => { "URI part length mustn't exceed 63 characters." }
            OriginError::FaultyPort => { "Port number was expected." }
        };

        write!(f, "{}", output)
    }
}
