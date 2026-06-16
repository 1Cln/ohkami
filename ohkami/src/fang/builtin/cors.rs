use crate::{Fang, FangProc, Request, Response, Status, header::append};
use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use super::OriginError;

// cors.rs
/* This replaces current `AccessControlAllowOrigin` */
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

impl Display for CorsOrigin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base_origin)
    }
}

#[derive(Debug)]
pub enum CorsOriginError {
    InvalidOrigin(OriginError)
}

impl Display for CorsOriginError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let CorsOriginError::InvalidOrigin(e) = self;
        write!(f, "{}", e)
    }
}

impl CorsOriginValue {
    /// Parse string based on the Cors origin string syntax.
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

                    let (cors_subdomain, cors_domain) = cors_origin.base_origin.host_as_subdomain_and_domain();
                    let (subdomain, domain) = host
                        .split_once('.')
                        .map_or((None, host), |(s, d)| {
                            if d.contains('.') {
                                (Some(s), d)
                            } else {
                                (None, host)
                            }
                        });

                    // If subdomain is not a wildcard, validate
                    if !cors_origin.any_subdomain && cors_subdomain != subdomain {
                        return false;
                    }

                    // Check if domain matches.
                    if domain != cors_domain {
                        return false;
                    }
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

    #[allow(unused)]
    fn matches(&self, incoming_origin: &super::Origin) -> bool {
        if self.is_any() {
            return true;
        }
        self.matches_str(incoming_origin.to_string().as_str())
    }

    fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }

    //     #[inline(always)]
    //     //This will perform expensive copy only if user provided dynamic string
    //     pub(crate) fn get_cow(&self) -> Cow<'static, str> {
    //         match self {
    //             Self::Any => Cow::Borrowed("*"),
    //             Self::Only(origin) => origin.clone(),
    //         }
    //     }
}

impl Display for CorsOriginValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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

// #[derive(Clone, Debug)]
// pub(crate) enum AccessControlAllowOrigin {
//     Any,
//     // `.access_control_allow_origin(...)` in the [`bite` impl](CorsProc::bite) requires accepts `Cow<'static, str>` so
//     // it will be cheap copy if user supplies as with static string ahead of time
//     Only(Cow<'static, str>),
// }
//
// impl AccessControlAllowOrigin {
//     #[inline(always)]
//     pub(crate) const fn is_any(&self) -> bool {
//         matches!(self, Self::Any)
//     }
//
//     pub(crate) fn new(s: impl Into<Cow<'static, str>>) -> Result<Self, &'static str> {
//         let s = s.into();
//         match s.as_ref() {
//             "*" => Ok(Self::Any),
//             _ => super::validate_origin(&s).map(|_| Self::Only(s)),
//         }
//     }
//
//     #[inline(always)]
//     //This will perform expensive copy only if user provided dynamic string
//     pub(crate) fn get_cow(&self) -> Cow<'static, str> {
//         match self {
//             Self::Any => Cow::Borrowed("*"),
//             Self::Only(origin) => origin.clone(),
//         }
//     }
// }

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
    fn cors_accept_regular_ip() {
        assert_eq!(
            "https://192.168.1.41:5173",
            super::Cors::verify_origin(
                "https://192.168.1.41:5173",
                &super::CorsOriginValue::new("https://192.168.1.41:5173").unwrap()
            )
        )
    }

    #[test]
    fn cors_accept_regular_domain() {
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
    fn cors_accept_localhost() {
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
    fn cors_accept_wildcard_in_ip_port() {
        assert_eq!(
            "https://192.168.1.2:5173",
            super::Cors::verify_origin(
                "https://192.168.1.2:5173",
                &super::CorsOriginValue::new("https://192.168.1.2:*").unwrap()
            )
        )
    }

    #[test]
    fn cors_accept_wildcard_in_port() {
        assert_eq!(
            "https://example.com:5173",
            super::Cors::verify_origin(
                "https://example.com:5173",
                &super::CorsOriginValue::new("https://example.com:*").unwrap()
            )
        )
    }

    #[test]
    fn cors_accept_wildcard_in_subdomain() {
        assert_eq!(
            "https://test.example.com",
            super::Cors::verify_origin(
                "https://test.example.com",
                &super::CorsOriginValue::new("https://*.example.com").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_wildcard_in_ip_subdomain() {
        assert_eq!(
            "https://192.168.1.15:8080/",
            super::Cors::verify_origin(
                "https://192.*.1.15:8080",
                &super::CorsOriginValue::new("https://192.168.1.15:8080").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_wildcard_in_sld() {
        assert_eq!(
            "https://test.example.com:8080/",
            super::Cors::verify_origin(
                "https://test.*.com:8080",
                &super::CorsOriginValue::new("https://test.example.com:8080").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_wildcard_in_extension() {
        assert_eq!(
            "https://test.example.com:8080/",
            super::Cors::verify_origin(
                "https://test.example.*:8080",
                &super::CorsOriginValue::new("https://test.example.com:8080").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_invalid_ip() {
        assert_eq!(
            "https://192.168.1.58:8080/",
            super::Cors::verify_origin(
                "https://192.168.a.58:8080",
                &super::CorsOriginValue::new("https://192.168.1.58:8080").unwrap()
            )
        )
    }

    #[test]
    fn cors_deny_invalid_ip_port_range() {
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
    #[should_panic(
        expected = "[Cors::new] Please use HTTP or HTTPS as scheme."
    )]
    fn cors_scheme_invalidation() {
        let _: super::Cors = super::Cors::new("foobarhttp://example.com");
    }

    #[test]
    #[should_panic(expected = "[Cors::new] URI length mustn't exceed 255 characters in total.")]
    fn cors_length_invalidation() {
        let a: super::Cors = super::Cors::new(
            "https://thisisaridiculouslylongurithatshoulddefinitelybeinvalidaccordingtothistest.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl.com",
        );
        println!("{}", a.allow_origin.to_string())
    }

    #[test]
    #[should_panic(expected = "[Cors::new] URI part length mustn't exceed 63 characters.")]
    fn cors_part_length_invalidation() {
        let _: super::Cors = super::Cors::new(
            "https://www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnoqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com",
        );
    }

    #[test]
    #[should_panic(
        expected = "[Cors::new] Port number was expected."
    )]
    fn cors_port_invalidation() {
        let _: super::Cors = super::Cors::new("http://example.com:abcd");
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
