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

fn validate_origin(origin: &str) -> Result<(), &'static str> {
    if origin.parse::<Uri>().is_ok() {
        Ok(())
    } else {
        Err("Unable to parse Uri.")
    }
}

// builtin.rs

/* #660 will replace this with an original struct
   (providing almost the same interface as this
   using original implementations internally)
*/
// Just wrapping `https::uri::Uri` for now
// to skip most difficult things in parsing,
// so we only have to handle HTTP-origin-specific rules
// on the top of the generic `Uri`.
struct Origin(Uri);

enum OriginError {
    InvalidUri(InvalidUri),
    InvalidScheme,
    InvalidPathLength,
    InvalidPartLength,
    InvalidPort,
    //...
}

enum Scheme {
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
            return Err(OriginError::InvalidScheme);
        }

        // Validate max path length
        if uri.path().chars().count() > u8::MAX as usize {
            return Err(OriginError::InvalidPathLength)
        }

        // Validate max part length
        if !uri.path().split('.').all(|part| part.chars().count() <= 63) {
            return Err(OriginError::InvalidPartLength)
        }

        // // Make sure port isn't made out of letters, and doesn't exceed `u16::MAX`
        // if let Some(port) = uri.port() {
        //     if !port.as_str().chars().all(|c| c.is_numeric()) {
        //         return Err(OriginError::InvalidPort)
        //     }
        // }

        // TODO: Add more if necessary

        Ok(Self(uri))
    }

    // Accessor methods for origin components; for example:
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

    fn host(&self) -> Option<&str> {
        self.0.host()
    }

    fn subdomain(&self) -> Option<&str> {
        if let Some(host) = self.0.host() {
            let (subdomain, _) = host
                .split_once('.')
                .map_or((None, host), |(s, r)| (Some(s), r));

            subdomain
        } else {
            None
        }
    }

    fn domain(&self) -> Option<&str> {
        if let Some(host) = self.0.host() {
            let (_, domain) = host
                .split_once('.')
                .map_or((None, host), |(s, r)| (Some(s), r));

            Some(domain)
        } else {
            None
        }
    }

    fn host_as_tuple(&self) -> (Option<&str>, &str) {
        if let Some(host) = self.0.host() {
            let (subdomain, domain) = host
                .split_once('.')
                .map_or((None, host), |(s, d)| (Some(s), d));

            (subdomain, domain)
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
