use welsib_tools::tools::base64::{base64_encode, base64_decode};

pub fn decode(str: &String) -> Vec<u8> {
    base64_decode(str.as_str())
}

pub fn encode(bytes: &Vec<u8>) -> String {
    base64_encode(bytes, false)
}

pub fn safe_decode(str: &String) -> Vec<u8> {
    base64_decode(str.as_str())
}

pub fn safe_encode(bytes: &Vec<u8>) -> String {
    base64_encode(bytes, true)
}