pub mod handshake;
pub mod send_slot;
pub mod send_point;
pub mod receive_slot;
pub mod send_bit_proof;

use crate::checksum::crc32;
use crate::conv::{
    u2vec::u2vec, slice2vec::slice2vec, vec2u::vec2u, vec2slice::vec2slice,
};
// use crate::smpc::WelsibDtoInterface;
use welsib_u512_ec::sign::Signature;
use welsib_json::{JsonValue, from_json, to_json};
use welsib_u512_ec::sign::welsib_sign;
use welsib_u512_ec::verify::welsib_verify;
use crate::hash::hash;
use welsib_u512_ec::point::Point;
use welsib_u512::u512::U512;
use std::collections::HashMap;

pub enum ResponseStatus {
    Success,
    Failed
}

#[derive(Debug, Clone)]
pub struct SMPCResponse {
    pub attributes: String,    // json
    pub signature_r: [u64; 8], // 512 bit
    pub signature_s: [u64; 8], // 512 bit
    pub checksum: u32,
}

impl SMPCResponse {
    pub fn make(attributes: String, private_key: &U512) -> Self {
        let attributes = attributes.replace("\"", "\\\"").replace("\\\\\"", "\\\"");
        let hash = hash(&attributes.as_bytes().to_vec());
        let Signature { r, s } = welsib_sign(&hash, private_key);
        // println!("Signature: {:#?} {:#?}", &r, &s);

        let signature_r = u2vec(r);
        let signature_s = u2vec(s);
        let checksum = crc32(
            &[
                attributes.clone().as_bytes().to_vec(),
                signature_r.clone(),
                signature_s.clone(),
            ]
            .concat(),
        );

        Self {
            attributes,
            signature_r: vec2slice(signature_r.clone()),
            signature_s: vec2slice(signature_s.clone()),
            checksum,
        }
    }

    pub fn from_frame(frame: &Vec<u8>) -> Option<Self> {
        // аутентификация
        let header_size: [u8; 4] = frame[0..4].try_into().unwrap_or_default();
        let cs = crc32(&header_size.to_vec());
        let checksum: [u8; 4] = frame[4..8].try_into().unwrap_or_default();
        crate::d(format!("Response (from_frame, control sum): {:?}, {:?}", &u32::from_be_bytes(checksum), &cs));
        if u32::from_be_bytes(checksum) != cs {
            crate::d(format!("контрольная сумма не верна"));
            None
        } else {
            crate::d(format!("контрольная сумма верна"));
            let json_bytes = frame[8..].to_vec();
            crate::d(format!("JSON bytes: {:?}", &json_bytes));
            let mut json = String::from_utf8(json_bytes).unwrap_or("".to_string());
            crate::d(format!("JSON: {:?}", &json));
            json.truncate(u32::from_be_bytes(header_size) as usize);
            crate::d(format!("JSON (truncated): {:?}", &json));
            Self::from_json(json.as_str())
        }
    }

    pub fn from_json(json: &str) -> Option<Self> {
        if let JsonValue::Object(obj) = from_json(json).unwrap() {
            let attributes = if let Some(JsonValue::String(attributes)) = obj.get("attributes") {
                attributes.clone().replace("\"", "\\\"").replace("\\\\\"", "\\\"")
            } else {
                return None;
            };

            let signature_r = if let Some(JsonValue::Array(signature_r)) = obj.get("signature_r") {
                signature_r.iter().map(|j_val| if let JsonValue::Number(v) = j_val { v.clone() } else { 0u64 /* NB! */ } ).collect::<Vec<u64>>()
                    .iter().map(|v| v.to_be_bytes()).collect::<Vec<_>>().concat()
            } else {
                return None;
            };

            let signature_s = if let Some(JsonValue::Array(signature_s)) = obj.get("signature_s") {
                signature_s.iter().map(|j_val| if let JsonValue::Number(v) = j_val { v.clone() } else { 0u64 /* NB! */ } ).collect::<Vec<u64>>()
                    .iter().map(|v| v.to_be_bytes()).collect::<Vec<_>>().concat()
            } else {
                return None;
            };

            let checksum = if let Some(JsonValue::Number(checksum)) = obj.get("checksum") {
                checksum.clone() as u32 // NB! mantissa
            } else {
                return None;
            };

            let cs_attributes = attributes.as_bytes().to_vec();
            let cs_signature_r = signature_r.to_vec();
            let cs_signature_s = signature_s.to_vec();
            let cs = crc32(&[cs_attributes, cs_signature_r, cs_signature_s].concat());
            if cs != checksum {
                // println!("Контрольная сумма SMPCResponse НЕ верна!");
                None
            } else {
                Some(Self {
                    attributes,
                    signature_r: vec2slice(signature_r.to_vec()),
                    signature_s: vec2slice(signature_s.to_vec()),
                    checksum,
                })
            }
        } else {
            None
        }
    }

    pub fn verify(&self, verify_key: &Point) -> bool {
        let signature = Signature {
            r: vec2u(slice2vec(self.signature_r)),
            s: vec2u(slice2vec(self.signature_s)),
        };
        let hash = hash(&self.attributes.as_bytes().to_vec());
        welsib_verify(&hash, &signature, verify_key)
    }

    pub fn to_frame(&self) -> Vec<u8> {
        let mut obj = HashMap::new();
        obj.insert(String::from("attributes"), JsonValue::String(self.attributes.clone()));
        obj.insert(String::from("signature_r"), JsonValue::Array(self.signature_r.clone().iter().map(|v| { JsonValue::Number(v.clone() as u64) }).collect::<Vec<_>>()));
        obj.insert(String::from("signature_s"), JsonValue::Array(self.signature_s.clone().iter().map(|v| { JsonValue::Number(v.clone() as u64) }).collect::<Vec<_>>()));
        obj.insert(String::from("checksum"), JsonValue::Number(self.checksum.clone() as u64));
        let json_obj = JsonValue::Object(obj);
        let json = to_json(&json_obj);
        let cs = crc32(&(json.len() as u32).to_be_bytes().to_vec());
        let mut bytes: Vec<u8> = [(json.len() as u32).to_be_bytes(), cs.to_be_bytes()].concat();
        bytes.append(&mut json.as_bytes().to_vec());
        bytes
    }
}

// impl WelsibDtoInterface for SMPCResponse {}
