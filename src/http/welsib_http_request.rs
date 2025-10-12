use crate::conv::u2vec::u2vec;
use crate::hash::hash;
use std::collections::HashMap;
use welsib_json::{JsonValue, from_json, to_json};
use crate::struct_to_bytes;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum RequestMethod {
    GET,
    POST,
    ACTIVATE,
}

impl RequestMethod {
    pub fn from_str(method: &str) -> Option<Self> {
        Some(match method {
            "GET" => Self::GET,
            "POST" => Self::POST,
            "ACTIVATE" => Self::ACTIVATE,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestLine {
    pub method: RequestMethod,
    pub uri: String,
    pub http_version: String,
}

impl RequestLine {
    pub fn from_string(line: &str) -> Option<Self> {
        let items = line.split(" ").collect::<Vec<&str>>();
        if items.len() != 3 {
            return None;
        }
        let method = match RequestMethod::from_str(items[0]) {
            Some(method) => method,
            None => return None,
        };
        let uri = String::from(items[1]);
        let http_version = String::from(items[2]);
        Some(Self {
            method,
            uri,
            http_version,
        })
    }
}

// https://datatracker.ietf.org/doc/html/rfc2616#section-4.5
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum GeneralHeader {
    CacheControl, // Cache-Control
    Connection,
    Date,
    Pragma,
    Trailer,
    TransferEncoding, // Transfer-Encoding
    Upgrade,
    Via,
    Warning,
}

impl GeneralHeader {
    pub fn to_string(&self) -> String {
        String::from(match self {
            Self::CacheControl => "Cache-Control",
            Self::Connection => "Connection",
            Self::Date => "Date",
            Self::Pragma => "Pragma",
            Self::Trailer => "Trailer",
            Self::TransferEncoding => "Transfer-Encoding",
            Self::Upgrade => "Upgrade",
            Self::Via => "Via",
            Self::Warning => "Warning",
            _ => "",
        })
    }
}

// https://datatracker.ietf.org/doc/html/rfc2616#section-5.3
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum RequestHeader {
    Accept,
    AcceptCharset,  // Accept-Charset
    AcceptEncoding, // Accept-Encoding
    AcceptLanguage, // Accept-Language
    Authorization,
    Expect,
    From,
    Host,
    IfMatch,            // If-Match
    IfModifiedSince,    // If-Modified-Since
    IfNoneMatch,        // If-None-Match
    IfRange,            // If-Range
    IfUnmodifiedSince,  // If-Unmodified-Since
    MaxForwards,        // Max-Forwards
    ProxyAuthorization, // Proxy-Authorization
    Range,
    Referer,
    TE,
    UserAgent, // User-Agent
}

// https://datatracker.ietf.org/doc/html/rfc2616#section-7.1
#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq)]
pub enum EntityHeader {
    Allow,
    ContentEncoding, // Content-Encoding
    ContentLanguage, // Content-Language
    ContentLength,   // Content-Length
    ContentLocation, // Content-Location
    ContentMD5,      // Content-MD5
    ContentRange,    // Content-Range
    ContentType,     // Content-Type
    Expires,
    LastModified, // Last-Modified
}

impl EntityHeader {
    pub fn to_string(&self) -> String {
        String::from(match self {
            Self::Allow => "Allow",
            Self::ContentEncoding => "Content-Encoding",
            Self::ContentLanguage => "Content-Language",
            Self::ContentLength => "Content-Length",
            Self::ContentLocation => "Content-Location",
            Self::ContentMD5 => "Content-MD5",
            Self::ContentRange => "Content-Range",
            Self::ContentType => "Content-Type",
            Self::Expires => "Expires",
            Self::LastModified => "Last-Modified",
            _ => "",
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WelsibHttpRequest {
    pub reqest_line: RequestLine,
    pub general_headers: HashMap<GeneralHeader, String>,
    pub request_headers: HashMap<RequestHeader, String>,
    pub entity_headers: HashMap<EntityHeader, String>,
    pub extension_headers: HashMap<String, String>, // X-
    pub message_body: Vec<u8>,
}

impl WelsibHttpRequest {
    pub fn from_string(request: String) -> Option<Self> {
        let lines = request.split("\r\n").collect::<Vec<&str>>();
        // println!("Lines (DEBUG): {:#?}", &lines);
        if lines.len() == 0 {
            return None;
        }
        let reqest_line = match RequestLine::from_string(lines[0]) {
            Some(reqest_line) => reqest_line,
            None => return None,
        };
        let mut general_headers = HashMap::new();
        let mut request_headers = HashMap::new();
        let mut entity_headers = HashMap::new();
        let mut extension_headers = HashMap::new();

        let mut message_body = vec![];
        if lines.len() > 1 {
            let position = lines.iter().position(|&y| y == "").unwrap_or_default();

            // Обработка заголовков входящего запроса
            for &line in lines[1..position].iter() {
                let splitted_header = line.split(":").collect::<Vec<&str>>();
                match splitted_header.first() {
                    Some(&header) => {
                        let general_header = match header {
                            "Cache-Control" => Some(GeneralHeader::CacheControl),
                            "Connection" => Some(GeneralHeader::Connection),
                            "Date" => Some(GeneralHeader::Date),
                            "Pragma" => Some(GeneralHeader::Pragma),
                            "Trailer" => Some(GeneralHeader::Trailer),
                            "Transfer-Encoding" => Some(GeneralHeader::TransferEncoding),
                            "Upgrade" => Some(GeneralHeader::Upgrade),
                            "Via" => Some(GeneralHeader::Via),
                            "Warning" => Some(GeneralHeader::Warning),
                            _ => None,
                        };
                        let request_header = if general_header.is_some() {
                            let _ = match general_header {
                                Some(general_header) => general_headers.insert(
                                    general_header,
                                    splitted_header[1..].join(":").trim_start().to_string(),
                                ),
                                None => None,
                            };
                            None
                        } else {
                            match header {
                                "Accept" => Some(RequestHeader::Accept),
                                "Accept-Charset" => Some(RequestHeader::AcceptCharset),
                                "Accept-Encoding" => Some(RequestHeader::AcceptEncoding),
                                "Accept-Language" => Some(RequestHeader::AcceptLanguage),
                                "Authorization" => Some(RequestHeader::Authorization),
                                "Expect" => Some(RequestHeader::Expect),
                                "From" => Some(RequestHeader::From),
                                "Host" => Some(RequestHeader::Host),
                                "If-Match" => Some(RequestHeader::IfMatch),
                                "If-Modified-Since" => Some(RequestHeader::IfModifiedSince),
                                "If-None-Match" => Some(RequestHeader::IfNoneMatch),
                                "If-Range" => Some(RequestHeader::IfRange),
                                "If-Unmodified-Since" => Some(RequestHeader::IfUnmodifiedSince),
                                "Max-Forwards" => Some(RequestHeader::MaxForwards),
                                "Proxy-Authorization" => Some(RequestHeader::ProxyAuthorization),
                                "Range" => Some(RequestHeader::Range),
                                "Referer" => Some(RequestHeader::Referer),
                                "TE" => Some(RequestHeader::TE),
                                "User-Agent" => Some(RequestHeader::UserAgent),
                                _ => None,
                            }
                        };
                        let entity_header = if general_header.is_some() || request_header.is_some()
                        {
                            let _ = match request_header {
                                Some(request_header) => request_headers.insert(
                                    request_header,
                                    splitted_header[1..].join(":").trim_start().to_string(),
                                ),
                                None => None,
                            };
                            None
                        } else {
                            match header {
                                "Allow" => Some(EntityHeader::Allow),
                                "Content-Encoding" => Some(EntityHeader::ContentEncoding),
                                "Content-Language" => Some(EntityHeader::ContentLanguage),
                                "Content-Length" => Some(EntityHeader::ContentLength),
                                "Content-Location" => Some(EntityHeader::ContentLocation),
                                "Content-MD5" => Some(EntityHeader::ContentMD5),
                                "Content-Range" => Some(EntityHeader::ContentRange),
                                "Content-Type" => Some(EntityHeader::ContentType),
                                "Expires" => Some(EntityHeader::Expires),
                                "Last-Modified" => Some(EntityHeader::LastModified),
                                _ => None,
                            }
                        };
                        if general_header.is_some()
                            || request_header.is_some()
                            || entity_header.is_some()
                        {
                            let _ = match entity_header {
                                Some(entity_header) => entity_headers.insert(
                                    entity_header,
                                    splitted_header[1..].join(":").trim_start().to_string(),
                                ),
                                None => None,
                            };
                        } else {
                            extension_headers.insert(
                                String::from(header.trim()),
                                splitted_header[1..].join(":").trim_start().to_string(),
                            );
                        };
                    }
                    None => {}
                };
            }

            if position > 0 {
                message_body = lines[position..].concat().as_bytes().to_vec();
            }
        }
        Some(Self {
            reqest_line,
            general_headers,
            request_headers,
            entity_headers,
            extension_headers,
            message_body,
        })
    }

    pub fn hash(&self) -> String {
        let bytes = unsafe { struct_to_bytes(self) };
        let hash = hash(&bytes.to_vec());
        u2vec(hash)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}
