use crate::{Fang, FangProc, Request, Response, Status, header::append};
use std::borrow::Cow;
use super::OriginError;

#[derive(Clone, Debug)]
pub enum CorsOriginValue {
    CorsOrigin(CorsOrigin),
    Any
}

#[derive(Clone, Debug)]
pub struct CorsOrigin {
    base_origin: super::Origin,
    any_port: bool,
    any_subdomain: bool,
}

impl std::fmt::Display for CorsOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base_origin)
    }
}

#[derive(Debug)]
pub enum CorsOriginError {
    InvalidOrigin(OriginError)
}

impl std::fmt::Display for CorsOriginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let CorsOriginError::InvalidOrigin(e) = self;
        write!(f, "{}", e)
    }
}

impl CorsOriginValue {
    /// Parse string based on the Cors origin string syntax.
    ///
    /// # Examples
    /// ```rust
    /// fn run() {
    ///     CorsOriginValue::new("https://localhost:3000").unwrap(); //Gives CorsOriginValue::CorsOrigin
    ///     CorsOriginValue::new("*").unwrap(); //Gives CorsOriginValue::Any
    /// }
    /// ```
    /// # Errors
    /// This function will return an error if the given URI string fails the validation included in [`Origin`].
    ///
    fn new(s: &str) -> Result<Self, CorsOriginError> {
        if s == "*" {
            return Ok(Self::Any);
        }

        let mut any_port = false;
        let mut any_subdomain = false;
        let mut s = match s.strip_suffix(":*") {
            Some(rest) => {
                any_port = true;
                Cow::Borrowed(rest)
            }
            None => Cow::Borrowed(s)
        };

        if let Some((scheme @ ("http://" | "https://"), rest)) = s.split_once("*.") {
            any_subdomain = true;
            // This allocation would not be a problem because `CorsOrigin::new` is
            // just called once in server initialization phase, not called repeatedly in request handling phases.
            s = Cow::Owned(scheme.to_string() + rest);
        }

        let base_origin = super::Origin::new(&s)
            .map_err(CorsOriginError::InvalidOrigin)?;

        Ok(Self::CorsOrigin(CorsOrigin { base_origin, any_port, any_subdomain }) )
    }

    /// Checks if according to the noted rules for wildcards in this struct, the incoming origin would match.
    ///
    /// # Examples
    /// ```
    /// fn run() {
    ///     let cors = CorsOriginValue::new("*").unwrap();
    ///     assert_eq!(true, cors.matches_str("localhost:5173")); // true
    /// }
    /// ```
    fn matches_str(&self, incoming_origin: &str) -> bool {
        match self {
            CorsOriginValue::CorsOrigin(cors_origin) => {
                if let Some(("http" | "https" , origin)) = incoming_origin.split_once("://") {
                    let (host, port) = origin
                        .split_once(':')
                        .map_or((origin, None), |(h, p)| (h, Some(p)));

                    // Check port if not wildcard, validate
                    if !cors_origin.any_port
                        && let Some(cors_port) = cors_origin.base_origin.port()
                        && Some(format!("{}", cors_port).as_str()) != port {
                        return false;
                    }

                    if let Some(cors_host) = cors_origin.base_origin.host() {
                        if !cors_origin.any_subdomain {
                            // If we do not support any subdomain, we can just fully compare the two, as no additional parsing is necessary.
                            if cors_host != host {
                                return false;
                            }
                        } else {
                            // Subdomain is a wildcard
                            // If they don't match, check if it's just a subdomain, or something else entirely, meaning it's invalid.
                            if cors_host != host {
                                // Returns None if strip fails, meaning some other unknown stuff was appended to the URI.
                                if None == host.strip_suffix(cors_host) {
                                    return false;
                                }
                            }
                        }
                    }
                    // If we do not support any subdomain, we can just fully compare the two, as no additional parsing is necessary.

                    // Subdomain, domain and port match, so return true.
                    true
                } else {
                    // No scheme was somehow found
                    false
                }
            }
            CorsOriginValue::Any => {
                // Anything goes
                true
            }
        }
    }

    /// Checks if according to the noted rules for wildcards in this struct, the incoming origin would match.
    ///
    /// # Examples
    /// ```
    /// fn run() {
    ///     let cors = CorsOriginValue::new("*").unwrap();
    ///     let origin = Origin::new("https://localhost:5173").unwrap();
    ///     assert_eq!(true, cors.matches(origin)); // true
    /// }
    /// ```
    #[allow(unused)]
    fn matches(&self, incoming_origin: &super::Origin) -> bool {
        if self.is_any() {
            return true;
        }
        self.matches_str(incoming_origin.to_string().as_str())
    }

    /// Returns if this [`CorsOriginValue`] is [`CorsOriginValue::Any`].
    fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }

}

impl std::fmt::Display for CorsOriginValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CorsOriginValue::CorsOrigin(origin) => {
                write!(f, "{}", origin)
            }
            CorsOriginValue::Any => {
                write!(f, "*")
            }
        }
    }
}

/// # Builtin fang for CORS config
///
/// <br>
///
/// *example.rs*
/// ```no_run
/// use ohkami::prelude::*;
/// use ohkami::fang::Cors;
///
/// #[tokio::main]
/// async fn main() {
///     Ohkami::new((
///         Cors::new("https://foo.bar.org")
///             .allow_headers(["Content-Type", "X-Requested-With"])
///             .allow_credentials(true)
///             .max_age(None),
///         "/api"
///             .GET(|| async {"Hello, CORS!"}),
///     )).howl("localhost:8080").await
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Cors {
    /* pub(crate) allow_methods: Option<String>, // owe to `Handler::default_not_found()` */
    pub(crate) allow_origin: CorsOriginValue,
    pub(crate) allow_credentials: bool,
    pub(crate) allow_headers: Option<String>,
    pub(crate) expose_headers: Option<String>,
    pub(crate) max_age: Option<u32>,
}

impl Cors {
    /// Create `Cors` fang using given `origin` as `Access-Control-Allow-Origin` header value.\
    /// (Both `"*"` and a specific origin are available)
    pub fn new(origin: impl Into<Cow<'static, str>>) -> Self {
        Self {
            allow_origin: CorsOriginValue::new(origin.into().as_ref())
                .unwrap_or_else(|err| panic!("[Cors::new] {err}")),
            allow_credentials: false,
            allow_headers: None,
            expose_headers: None,
            max_age: None,
        }
    }

    #[inline]
    /// Creates `Cors` with any origin allowed
    pub const fn any() -> Self {
        Self {
            allow_origin: CorsOriginValue::Any,
            allow_credentials: false,
            allow_headers: None,
            expose_headers: None,
            max_age: None,
        }
    }

    pub fn allow_credentials(mut self, yes: bool) -> Self {
        if yes {
            if self.allow_origin.is_any() {
                #[cfg(debug_assertions)]
                {
                    crate::WARNING!(
                        "\
                        'Access-Control-Allow-Origin' header \
                        must not have wildcard '*' when the request's credentials mode is 'include' \
                    "
                    );
                }
                return self;
            }
            self.allow_credentials = true;
        } else {
            self.allow_credentials = false;
        }
        self
    }
    pub fn allow_headers<const N: usize>(mut self, headers: [&'static str; N]) -> Self {
        self.allow_headers = (!headers.is_empty()).then_some(headers.join(", "));
        self
    }
    pub fn expose_headers<const N: usize>(mut self, headers: [&'static str; N]) -> Self {
        self.expose_headers = (!headers.is_empty()).then_some(headers.join(", "));
        self
    }
    pub fn max_age(mut self, delta_seconds: Option<u32>) -> Self {
        self.max_age = delta_seconds;
        self
    }
    pub fn verify_origin<'a>(origin: &'a str, cors_origin: &CorsOriginValue) -> Cow<'a, str> {
        if CorsOriginValue::matches_str(cors_origin, origin) {
            Cow::Borrowed(origin)
        } else {
            Cow::Owned(cors_origin.to_string())
        }
    }
}

impl<Inner: FangProc> Fang<Inner> for Cors {
    type Proc = CorsProc<Inner>;
    fn chain(&self, inner: Inner) -> Self::Proc {
        CorsProc {
            inner,
            cors: self.clone(),
        }
    }
}

pub struct CorsProc<Inner: FangProc> {
    cors: Cors,
    inner: Inner,
}
/* Based on https://github.com/honojs/hono/blob/main/src/middleware/cors/index.ts; MIT */
impl<Inner: FangProc> FangProc for CorsProc<Inner> {
    async fn bite<'b>(&'b self, req: &'b mut Request) -> Response {
        let mut res = self.inner.bite(req).await;
        let allow_origin = Cors::verify_origin(
            req.headers.origin().unwrap_or(""),
            &self.cors.allow_origin,
        )
        .into_owned();

        res.headers
            .set()
            .access_control_allow_origin(allow_origin)
            .vary(self.cors.allow_origin.is_any().then_some("Origin".into()))
            .access_control_allow_credentials(self.cors.allow_credentials.then_some("true".into()))
            .access_control_expose_headers(
                self.cors
                    .expose_headers
                    .as_ref()
                    .map(|s| s.to_string().into()),
            );
        if req.method.isOPTIONS() {
            res.headers
                .set()
                .access_control_max_age(self.cors.max_age.map(|v| v.to_string().into()));
            if let Some(allow_headers) = self.cors.allow_headers.as_ref()
                && !allow_headers.is_empty()
            {
                res.headers
                    .set()
                    .access_control_allow_headers(allow_headers.to_string())
                    .vary(append("Access-Control-Request-Headers"));
            }
            if res.status == Status::NotImplemented {
                // override default `NotImplemented` response for valid preflight.
                // see `Handler::default_not_found()`.
                res.status = Status::OK;
                res.headers.set().content_type(None).content_length(None);
            }
        }

        crate::DEBUG!("After CORS proc: res = {res:#?}");

        res
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn cors_accept_regular_origin_ip() {
        assert_eq!(
            "https://192.168.1.41:5173",
            super::Cors::verify_origin(
                "https://192.168.1.41:5173",
                &super::CorsOriginValue::new("https://192.168.1.41:5173").unwrap()
            )
        )
    }

    #[test]
    fn cors_accept_regular_origin_domain() {
        assert_eq!(
            "https://example.com",
            super::Cors::verify_origin(
                "https://example.com",
                &super::CorsOriginValue::new("https://example.com").unwrap()
            )
        );
        assert_eq!(
            "https://sub.example.com",
            super::Cors::verify_origin(
                "https://sub.example.com",
                &super::CorsOriginValue::new("https://sub.example.com").unwrap()
            )
        )
    }

    #[test]
    fn cors_accept_origin_localhost() {
        assert_eq!(
            "https://localhost:5173/",
            super::Cors::verify_origin(
                "https://localhost:5173/",
                &super::CorsOriginValue::new("https://localhost:5173/").unwrap()
            )
        );
        assert_eq!(
            "https://localhost:5173",
            super::Cors::verify_origin(
                "https://localhost:5173",
                &super::CorsOriginValue::new("https://localhost:*").unwrap()
            )
        )
    }

    #[test]
    fn cors_accept_wildcard_match_in_own_ip_port() {
        assert_eq!(
            "https://192.168.1.2:5173",
            super::Cors::verify_origin(
                "https://192.168.1.2:5173",
                &super::CorsOriginValue::new("https://192.168.1.2:*").unwrap()
            )
        )
    }

    #[test]
    fn cors_accept_wildcard_match_in_own_port() {
        assert_eq!(
            "https://example.com:5173",
            super::Cors::verify_origin(
                "https://example.com:5173",
                &super::CorsOriginValue::new("https://example.com:*").unwrap()
            )
        )
    }

    #[test]
    fn cors_accept_wildcard_match_in_own_subdomain() {
        assert_eq!(
            "https://test.example.com",
            super::Cors::verify_origin(
                "https://test.example.com",
                &super::CorsOriginValue::new("https://*.example.com").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_wildcard_in_origin_ip_subdomain() {
        assert_eq!(
            "https://192.168.1.15:8080/",
            super::Cors::verify_origin(
                "https://*.168.1.15:8080",
                &super::CorsOriginValue::new("https://192.168.1.15:8080").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_faulty_wildcard_in_origin_ip() {
        assert_eq!(
            "https://192.168.1.15:8080/",
            super::Cors::verify_origin(
                "https://192.*.1.15:8080",
                &super::CorsOriginValue::new("https://192.168.1.15:8080").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_faulty_wildcard_in_origin_ip_subdomain() {
        assert_eq!(
            "https://192.168.1.15:8080/",
            super::Cors::verify_origin(
                "https://*.168.1.15:8080",
                &super::CorsOriginValue::new("https://192.168.1.15:8080").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_wildcard_in_origin_sld() {
        assert_eq!(
            "https://test.example.com:8080/",
            super::Cors::verify_origin(
                "https://test.*.com:8080",
                &super::CorsOriginValue::new("https://test.example.com:8080").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_wildcard_in_origin_extension() {
        assert_eq!(
            "https://test.example.com:8080/",
            super::Cors::verify_origin(
                "https://test.example.*:8080",
                &super::CorsOriginValue::new("https://test.example.com:8080").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_invalid_origin_ip() {
        assert_eq!(
            "https://192.168.1.58:8080/",
            super::Cors::verify_origin(
                "https://192.168.a.58:8080",
                &super::CorsOriginValue::new("https://192.168.1.58:8080").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_invalid_origin_ip_port_range() {
        assert_eq!(
            "https://192.168.1.0:8080/",
            super::Cors::verify_origin(
                "https://192.168.1.0:80080",
                &super::CorsOriginValue::new("https://192.168.1.0:8080").unwrap()
            )
        )
    }

    #[test]
    fn cors_new_with_str_or_string() {
        let _: super::Cors = super::Cors::new("https://example.com");
        let _: super::Cors = super::Cors::new(String::from("https://") + "example.com");
    }

    #[test]
    fn cors_wildcard_validation() {
        let _: super::Cors = super::Cors::new("https://*.example.com");
        let _: super::Cors = super::Cors::new("https://example.com:*");
        let _: super::Cors = super::Cors::new("https://*.example.com:*");
        let _: super::Cors = super::Cors::new("http://123example.com");
        let _: super::Cors = super::Cors::new(
            "https://abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcde.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.com",
        );
    }

    #[test]
    fn cors_scheme_invalidation() {
        let origin = "foobarhttp://example.com";
        assert_eq!(super::CorsOriginError::InvalidOrigin(super::OriginError::FaultyScheme).to_string(), super::CorsOriginValue::new(origin).unwrap_err().to_string())
    }

    #[test]
    fn cors_length_invalidation() {
        let origin = "https://thisisaridiculouslylongurithatshoulddefinitelybeinvalidaccordingtothistest.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl.com";
        assert_eq!(super::CorsOriginError::InvalidOrigin(super::OriginError::FaultyUriLength).to_string(), super::CorsOriginValue::new(origin).unwrap_err().to_string())
    }

    #[test]
    fn cors_part_length_invalidation() {
        let origin = "https://www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnoqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com";
        assert_eq!(super::CorsOriginError::InvalidOrigin(super::OriginError::FaultyUriPartLength).to_string(), super::CorsOriginValue::new(origin).unwrap_err().to_string())
    }

    #[test]
    fn cors_port_invalidation() {
        let origin = "http://example.com:abcd";
        assert_eq!(super::CorsOriginError::InvalidOrigin(super::OriginError::FaultyPort).to_string(), super::CorsOriginValue::new(origin).unwrap_err().to_string())
    }

    #[test]
    fn cors_ip_subdomain_wildcard_invalidation() {
        let origin = "https://*.168.1.0:8080";
        assert_eq!(super::CorsOriginError::InvalidOrigin(super::OriginError::FaultyIp).to_string(), super::CorsOriginValue::new(origin).unwrap_err().to_string())
    }

    #[test]
    #[should_panic(
        expected = "[Cors::new] Invalid URI."
    )]
    fn cors_host_invalidation() {
        let _: super::Cors = super::Cors::new("http://%example.com");
    }

    #[test]
    fn cors_fang_bound() {
        use crate::fang::{BoxedFPC, Fang};
        fn assert_fang<T: Fang<BoxedFPC>>() {}

        assert_fang::<super::Cors>();
    }

    #[cfg(all(feature = "__rt_native__", feature = "DEBUG"))]
    #[test]
    fn options_request() {
        use super::Cors;
        use crate::prelude::*;
        use crate::testing::*;

        crate::__rt__::testing::block_on(async {
            let t = Ohkami::new("/hello".POST(|| async { "Hello!" })).test();
            {
                let req = TestRequest::OPTIONS("/");
                let res = t.oneshot(req).await;
                assert_eq!(res.status(), Status::NotFound);
            }
            {
                let req = TestRequest::OPTIONS("/hello");
                let res = t.oneshot(req).await;
                assert_eq!(res.status(), Status::NotFound);
                assert_eq!(res.text(), None);
            }

            let t = Ohkami::new((
                Cors::new("https://example.x.y.z"),
                "/hello".POST(|| async { "Hello!" }),
            ))
            .test();
            {
                let req = TestRequest::OPTIONS("/");
                let res = t.oneshot(req).await;
                assert_eq!(res.status(), Status::NotFound);
            }
            {
                let req = TestRequest::OPTIONS("/hello");
                let res = t.oneshot(req).await;
                assert_eq!(res.status(), Status::NotFound);
                assert_eq!(res.text(), None);
            }
            {
                let req = TestRequest::OPTIONS("/hello")
                    .header("Access-Control-Request-Method", "DELETE");
                let res = t.oneshot(req).await;
                assert_eq!(
                    res.status(),
                    Status::BadRequest /* Because `DELETE` is not available */
                );
                assert_eq!(res.text(), None);
            }
            {
                let req =
                    TestRequest::OPTIONS("/hello").header("Access-Control-Request-Method", "POST");
                let res = t.oneshot(req).await;
                assert_eq!(
                    res.status(),
                    Status::OK /* Becasue `POST` is available */
                );
                assert_eq!(res.text(), None);
            }
        });
    }

    #[cfg(all(feature = "__rt_native__", feature = "DEBUG"))]
    #[test]
    fn cors_headers() {
        use super::Cors;
        use crate::prelude::*;
        use crate::testing::*;

        crate::__rt__::testing::block_on(async {
            let t = Ohkami::new((
                Cors::new("https://example.example"),
                "/".GET(|| async { "Hello!" }),
            ))
            .test();
            {
                let req = TestRequest::GET("/");
                let res = t.oneshot(req).await;

                assert_eq!(res.status().code(), 200);
                assert_eq!(res.text(), Some("Hello!"));

                assert_eq!(
                    res.header("Access-Control-Allow-Origin"),
                    Some("https://example.example")
                );
                assert_eq!(res.header("Access-Control-Allow-Credentials"), None);
                assert_eq!(res.header("Access-Control-Expose-Headers"), None);
                assert_eq!(res.header("Access-Control-Max-Age"), None);
                assert_eq!(res.header("Access-Control-Allow-Methods"), None);
                assert_eq!(res.header("Access-Control-Allow-Headers"), None);
                assert_eq!(res.header("Vary"), None);
            }

            let t = Ohkami::new((
                Cors::new("https://example.example")
                    .allow_credentials(true)
                    .allow_headers(["Content-Type", "X-Custom"]),
                "/abc".GET(|| async { "Hello!" }).PUT(|| async { "Hello!" }),
            ))
            .test();
            {
                let req = TestRequest::OPTIONS("/abc");
                let res = t.oneshot(req).await;

                assert_eq!(
                    res.status().code(),
                    404 /* Because `req` has no `Access-Control-Request-Method` */
                );
                assert_eq!(res.text(), None);

                assert_eq!(
                    res.header("Access-Control-Allow-Origin"),
                    Some("https://example.example")
                );
                assert_eq!(res.header("Access-Control-Allow-Credentials"), Some("true"));
                assert_eq!(res.header("Access-Control-Expose-Headers"), None);
                assert_eq!(res.header("Access-Control-Max-Age"), None);
                assert_eq!(
                    res.header("Access-Control-Allow-Methods"),
                    None /* Because `req` has no `Access-Control-Request-Method` */
                );
                assert_eq!(
                    res.header("Access-Control-Allow-Headers"),
                    Some("Content-Type, X-Custom")
                );
                assert_eq!(res.header("Vary"), Some("Access-Control-Request-Headers"));
            }
            {
                let req =
                    TestRequest::OPTIONS("/abc").header("Access-Control-Request-Method", "PUT");
                let res = t.oneshot(req).await;

                assert_eq!(
                    res.status().code(),
                    200 /* Because `req` HAS available `Access-Control-Request-Method` */
                );
                assert_eq!(res.text(), None);

                assert_eq!(
                    res.header("Access-Control-Allow-Origin"),
                    Some("https://example.example")
                );
                assert_eq!(res.header("Access-Control-Allow-Credentials"), Some("true"));
                assert_eq!(res.header("Access-Control-Expose-Headers"), None);
                assert_eq!(res.header("Access-Control-Max-Age"), None);
                assert_eq!(
                    res.header("Access-Control-Allow-Methods"),
                    Some("GET, PUT, HEAD, OPTIONS") /* Because `req` HAS a `Access-Control-Request-Method` */
                );
                assert_eq!(
                    res.header("Access-Control-Allow-Headers"),
                    Some("Content-Type, X-Custom")
                );
                assert_eq!(res.header("Vary"), Some("Access-Control-Request-Headers"));
            }
            {
                let req =
                    TestRequest::OPTIONS("/abc").header("Access-Control-Request-Method", "DELETE");
                let res = t.oneshot(req).await;

                assert_eq!(
                    res.status().code(),
                    400 /* Because `DELETE` is not available */
                );
                assert_eq!(res.text(), None);

                assert_eq!(
                    res.header("Access-Control-Allow-Origin"),
                    Some("https://example.example")
                );
                assert_eq!(res.header("Access-Control-Allow-Credentials"), Some("true"));
                assert_eq!(res.header("Access-Control-Expose-Headers"), None);
                assert_eq!(res.header("Access-Control-Max-Age"), None);
                assert_eq!(
                    res.header("Access-Control-Allow-Methods"),
                    Some("GET, PUT, HEAD, OPTIONS") /* Because `req` HAS a `Access-Control-Request-Method` */
                );
                assert_eq!(
                    res.header("Access-Control-Allow-Headers"),
                    Some("Content-Type, X-Custom")
                );
                assert_eq!(res.header("Vary"), Some("Access-Control-Request-Headers"));
            }
            {
                let req = TestRequest::PUT("/abc");
                let res = t.oneshot(req).await;

                assert_eq!(res.status().code(), 200);
                assert_eq!(res.text(), Some("Hello!"));

                assert_eq!(
                    res.header("Access-Control-Allow-Origin"),
                    Some("https://example.example")
                );
                assert_eq!(res.header("Access-Control-Allow-Credentials"), Some("true"));
                assert_eq!(res.header("Access-Control-Expose-Headers"), None);
                assert_eq!(res.header("Access-Control-Max-Age"), None);
                assert_eq!(res.header("Access-Control-Allow-Methods"), None);
                assert_eq!(res.header("Access-Control-Allow-Headers"), None);
                assert_eq!(res.header("Vary"), None);
            }

            let t = Ohkami::new((
                Cors::new("*")
                    .allow_headers(["Content-Type", "X-Custom"])
                    .max_age(Some(1024)),
                "/".POST(|| async { "Hello!" }),
            ))
            .test();
            {
                let req = TestRequest::OPTIONS("/");
                let res = t.oneshot(req).await;

                assert_eq!(
                    res.status().code(),
                    404 /* Because `req` has no `Access-Control-Request-Method` */
                );
                assert_eq!(res.text(), None);

                assert_eq!(res.header("Access-Control-Allow-Origin"), Some("*"));
                assert_eq!(res.header("Access-Control-Allow-Credentials"), None);
                assert_eq!(res.header("Access-Control-Expose-Headers"), None);
                assert_eq!(res.header("Access-Control-Max-Age"), Some("1024"));
                assert_eq!(
                    res.header("Access-Control-Allow-Methods"),
                    None /* Because `req` has no `Access-Control-Request-Method` */
                );
                assert_eq!(
                    res.header("Access-Control-Allow-Headers"),
                    Some("Content-Type, X-Custom")
                );
                assert_eq!(
                    res.header("Vary"),
                    Some("Origin, Access-Control-Request-Headers")
                );
            }
            {
                let req = TestRequest::OPTIONS("/").header("Access-Control-Request-Method", "POST");
                let res = t.oneshot(req).await;

                assert_eq!(res.status().code(), 200);
                assert_eq!(res.text(), None);

                assert_eq!(res.header("Access-Control-Allow-Origin"), Some("*"));
                assert_eq!(res.header("Access-Control-Allow-Credentials"), None);
                assert_eq!(res.header("Access-Control-Expose-Headers"), None);
                assert_eq!(res.header("Access-Control-Max-Age"), Some("1024"));
                assert_eq!(
                    res.header("Access-Control-Allow-Methods"),
                    Some("POST, OPTIONS")
                );
                assert_eq!(
                    res.header("Access-Control-Allow-Headers"),
                    Some("Content-Type, X-Custom")
                );
                assert_eq!(
                    res.header("Vary"),
                    Some("Origin, Access-Control-Request-Headers")
                );
            }
        });
    }
}
