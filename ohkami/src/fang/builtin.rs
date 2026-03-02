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

fn validate_origin(origin: &str) -> Result<(), &'static str> {
    //Adds a check for the first characters being http or https, so it cannot be malformed like foobarhttp://example.org/
    if !origin.starts_with("http") {
        return Err("invalid origin: 'http' or 'https' scheme is required at the start of the string.")
    }
    let Some(("http" | "https", rest)) = origin.split_once("://") else {
        return Err("invalid origin: 'http' or 'https' scheme is required.");
    };
    let (host, port) = rest
        .split_once(':')
        .map_or((rest, None), |(h, p)| (h, Some(p)));
    if port.is_some_and(|p| !p.chars().all(|c| c.is_ascii_digit() || c == '*')) {
        return Err("invalid origin: port must be a number or wildcard '*'.");
    }
    if !host.starts_with(|c: char| c.is_ascii_alphabetic() || c == '*') {
        return Err("invalid origin: host must start with an alphabetic character or wildcard '*'.");
    }
    if !host.split('.').all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '*'))
    }) {
        if host.contains(['/', '?', '#']) {
            // helpful error message for common mistake
            return Err("invalid origin: path, query and fragment are not allowed.");
        } else {
            return Err("invalid origin: invalid host.");
        }
    }
    Ok(())
}
