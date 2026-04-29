use axum::{Json, response::IntoResponse};
use gix_actor::bstr::ByteSlice as _;
use headers::authorization::Credentials;
use http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
use serde::{Serialize, Serializer};

#[derive(Clone, PartialEq, Debug)]
pub struct Token(String);
impl Token {
    /// View the token part as a `&str`.
    pub fn token(&self) -> &str {
        self.0.as_str()["Token ".len()..].trim_start()
    }
}
impl Credentials for Token {
    const SCHEME: &'static str = "Token";

    fn decode(value: &HeaderValue) -> Option<Self> {
        debug_assert!(
            value.as_bytes()[..Self::SCHEME.len()]
                .eq_ignore_ascii_case(Self::SCHEME.as_bytes()),
            "HeaderValue to decode should start with \"Token ..\", received = {:?}",
            value,
        );
        value.to_str().ok().map(Into::into).map(Token)
    }
    fn encode(&self) -> HeaderValue {
        (&self.0)
            .try_into()
            .expect("a string to always be a valid header value")
    }
}

pub fn auth_for_schemes<'map>(
    schemes: &[&[u8]],
    headers: &'map HeaderMap<HeaderValue>,
) -> Option<&'map [u8]> {
    let (scheme, parameters) = headers
        .get(AUTHORIZATION)?
        .as_bytes()
        .split_once_str(b" ")?;

    std::iter::zip(schemes, std::iter::repeat(scheme))
        .any(|(a, b)| a.eq_ignore_ascii_case(b))
        .then_some(parameters)
}

#[derive(Serialize, Debug)]
pub struct Error {
    #[serde(serialize_with = "status_to_string")]
    pub(super) status: http::StatusCode,
    pub(super) documentation_url: String,
    pub(super) message: String,
}
impl Error {
    pub fn unauthorized() -> Self {
        Self {
            status: http::StatusCode::UNAUTHORIZED,
            documentation_url: "https://docs.github.com/rest".into(),
            message: "Requires authentication".into(),
        }
    }
}

fn status_to_string<S>(st: &http::StatusCode, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    st.as_str().serialize(ser)
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(self)).into_response()
    }
}
