use super::welsib_http_request::{EntityHeader, GeneralHeader};
use std::collections::HashMap;

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum ResponseHeader {
    AcceptRanges, // Accept-Ranges
    Age,
    ETag,
    Location,
    ProxyAuthenticate, // Proxy-Authenticate
    RetryAfter,        // Retry-After
    Server,
    Vary,
    WWWAuthenticate, // WWW-Authenticate
}

impl ResponseHeader {
    pub fn to_string(&self) -> String {
        String::from(match self {
            Self::AcceptRanges => "Accept-Ranges",
            Self::Age => "Age",
            Self::ETag => "ETag",
            Self::Location => "Location",
            Self::ProxyAuthenticate => "Proxy-Authenticate",
            Self::RetryAfter => "Retry-After",
            Self::Server => "Server",
            Self::Vary => "Vary",
            Self::WWWAuthenticate => "WWW-Authenticate",
            _ => "",
        })
    }
}

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum WelsibResponseHeader {
    XSignature,
    XPublicKey,
    XCurveParameters,
}

impl WelsibResponseHeader {
    pub fn to_string(&self) -> String {
        String::from(match self {
            Self::XSignature => "X-Welsib-Signature",
            Self::XPublicKey => "X-Welsib-Public-Key",
            Self::XCurveParameters => "X-Welsib-Curve-Parameters",
            _ => "",
        })
    }
}

// https://datatracker.ietf.org/doc/html/rfc2616#section-6.1.1
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum ReasonPhrase {
    SwitchingProtocols, // Switching Protocols
    Ok,                 // OK
    BadRequest,         // Bad Request
    NotFound,           // Not Found
    InternalServerError, // Internal Server Error
                        // TODO: добавить остальные значения
}

impl ReasonPhrase {
    pub fn to_string(&self) -> String {
        String::from(match self {
            Self::SwitchingProtocols => "Switching Protocols",
            Self::Ok => "OK",
            Self::BadRequest => "Bad Request",
            Self::NotFound => "Not Found",
            Self::InternalServerError => "Internal Server Error",
            _ => "Internal Server Error",
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatusLine {
    pub http_version: String,
    pub status_code: u16,
    pub reason_phrase: ReasonPhrase,
}

impl StatusLine {
    pub fn to_string(&self) -> String {
        [
            self.http_version.clone(),
            self.status_code.to_string(),
            self.reason_phrase.to_string(),
        ]
        .join(" ")
    }
}

// https://datatracker.ietf.org/doc/html/rfc2616#section-6
#[derive(Debug, Clone, PartialEq)]
pub struct WelsibHttpResponse {
    pub status_line: StatusLine,
    pub general_headers: HashMap<GeneralHeader, String>,
    pub response_headers: HashMap<ResponseHeader, String>,
    pub entity_headers: HashMap<EntityHeader, String>,
    pub extension_headers: HashMap<String, String>, // X-
    pub message_body: Vec<u8>,
}

impl WelsibHttpResponse {
    pub fn new(status_code: u16) -> Self {
        let status_code = if status_code < 100 || status_code > 999 {
            500
        } else {
            status_code
        };
        let status_line = StatusLine {
            http_version: String::from("HTTP/1.1"),
            status_code,
            reason_phrase: match status_code {
                101 => ReasonPhrase::SwitchingProtocols,
                200 => ReasonPhrase::Ok,
                400 => ReasonPhrase::BadRequest,
                404 => ReasonPhrase::NotFound,
                500 => ReasonPhrase::InternalServerError,
                // TODO: добавить остальные значения
                _ => ReasonPhrase::InternalServerError,
            },
        };
        Self {
            status_line,
            general_headers: HashMap::new(),
            response_headers: HashMap::new(),
            entity_headers: HashMap::new(),
            extension_headers: HashMap::new(),
            message_body: vec![],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let general_headers = self
            .general_headers
            .iter()
            .map(|(h, v)| format!("{}: {}", h.to_string(), v))
            .collect::<Vec<String>>();
        let response_headers = self
            .response_headers
            .iter()
            .map(|(h, v)| format!("{}: {}", h.to_string(), v))
            .collect::<Vec<String>>();
        let entity_headers = self
            .entity_headers
            .iter()
            .map(|(h, v)| format!("{}: {}", h.to_string(), v))
            .collect::<Vec<String>>();
        let extension_headers = self
            .extension_headers
            .iter()
            .map(|(h, v)| format!("{}: {}", h, v))
            .collect::<Vec<String>>();

        let header = [
            self.status_line.to_string(),
            general_headers.join("\r\n"),
            response_headers.join("\r\n"),
            entity_headers.join("\r\n"),
            extension_headers.join("\r\n"),
        ]
        .iter()
        .filter(|v| v.len() > 0)
        .map(|v| v.clone())
        .collect::<Vec<String>>()
        .join("\r\n");

        if self.message_body.len() == 0 {
            header.as_bytes().to_vec()
        } else {
            [
                (header + "\r\n\r\n").as_bytes().to_vec(),
                self.message_body.clone(),
            ]
            .concat()
        }
    }
}
