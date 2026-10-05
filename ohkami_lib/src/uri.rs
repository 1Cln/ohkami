use std::borrow::Cow;
/*
    HTTP  origin (scheme(http|https) + host(domain|ip) + (port)?) parser is needed for at least `Cors` and `Csrf` middlewares.
    requirements:
    - Provides field type option for both (non-`static`) reference and owned `String`. ( Cow<'a, str> resolves this.)
        - Config values are desired to be owned string for some use-cases like `env::var`.
        - Incoming origin values from `&req Request` should be `'req` references to avoid unneeded clones.
    - Shouldn't contain unneeded fields for this use-case (e.g. path, query, etc.).

    Additional functional requirements are:
    - Non-ascii characters (punycode) handling.
    - IPv6 host handling

    `/ohkami_lib/.*`
*/

const MAX_LEN: usize = (u16::MAX - 1) as usize;

#[derive(PartialEq)]
pub enum Scheme {
    Http,
    Https,
}

pub enum OriginType {
    Ipv4,
    Ipv6,
    Domain,
}

pub struct BaseUri<'a> {
    subdomain: Option<Cow<'a, str>>,
    domain: Cow<'a, str>,
    port: Option<u16>,
}

#[derive(Debug, PartialEq)]
pub enum UriParseError {
    MalformedUri,
    IncompleteUri,
}

impl std::fmt::Display for UriParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let output = match self {
            UriParseError::IncompleteUri => {
                "Uri is missing some parts causing it to be unable to be parsed."
            }
            UriParseError::MalformedUri => "Uri is malformed, couldn't parse.",
        };
        write!(f, "{}", output)
    }
}

pub struct Uri<'a> {
    uri_type: OriginType,
    scheme: Scheme,
    base: BaseUri<'a>,
}

impl Uri<'_> {
    // fn from_bytes(s: Bytes) {
    //
    // }

    // pub fn parse(s: Cow<'_, str>) -> Result<Self, UriParseError> {
    //     if let Some((scheme @ ("http://" | "https://"), host)) = &s.split_once("*.") {
    //         if let Some((host, port)) = host.rsplit_once(":") {
    //             let uri_type = return match host.parse::<core::net::IpAddr>() {
    //                 Ok(ip) if ip.is_ipv4() => {
    //                     Ok(
    //                         Self {
    //                             uri_type: OriginType::Ipv4,
    //                             scheme: match scheme {
    //                                 &"http" => Scheme::Http,
    //                                 _ => Scheme::Https,
    //                             },
    //                             base: BaseUri { subdomain: None, domain: host.into(), port: port.parse::<u16>().map_or(None, |p| Some(p)) },
    //                         }
    //                     )
    //                 },
    //                 Ok(_) => {
    //                     // If parsed successfully but not IPv4, the only other option is IPv6
    //                     Ok(
    //                         Self {
    //                             uri_type: OriginType::Ipv6,
    //                             scheme: match scheme {
    //                                 &"http" => Scheme::Http,
    //                                 _ => Scheme::Https,
    //                             },
    //                             base: BaseUri { subdomain: None, domain: host.into(), port: port.parse::<u16>().map_or(None, |p| Some(p)) },
    //                         }
    //                     )
    //                 },
    //                 Err(_) => {
    //                     Err(UriParseError::MalformedUri)
    //                 }
    //             };
    //         } else {
    //             Err(UriParseError::MalformedUri)
    //         }
    //     } else {
    //         Err(UriParseError::MalformedUri)
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    #[test]
    fn uri_to_bytes() {
        let emoji: Cow<'static, &str> = Cow::Owned("😀");
        // println!("{:?}", emoji.bytes());

        let complex_emoji: Cow<'static, &str> = Cow::Owned("🏳️‍🌈 | 👨‍👨‍👦‍👦 | 🏳️‍⚧️");
        // println!("{:?}", complex_emoji.bytes());
        println!("{:?}", complex_emoji.to_ascii_lowercase());
        println!("{:?}", 0x80);
    }
}
