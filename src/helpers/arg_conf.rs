use std::fs;
use std::path::PathBuf;
use crate::conv::hex2vec::hex2vec;
use crate::conv::vec2u::vec2u;
use welsib_json::{JsonValue, from_json, to_json};
use welsib_u512_ec::point::Point;
use welsib_tools::tools::keys::pem_point_input::WelsibPointInput;
use welsib_tools::tools::base64::base64_decode;

#[derive(Debug, Clone)]
pub struct Config {
    public_keys: Vec<Point>,
}

impl Config {
    pub fn read(filename: String) -> std::io::Result<Self> {
        if filename.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidFilename,
                "Имя файла не может быть пустым",
            ));
        }

        let path = PathBuf::from(filename);

        if !fs::exists(&path)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Файл {:?} не найден", path),
            ));
        }

        let public_keys = fs::read_to_string(&path)?.trim().split("\n").map(|pem_public_key_filename| {
            let base64_point = WelsibPointInput::read_file(PathBuf::from(pem_public_key_filename))?.input;
            let point_bytes = base64_decode(base64_point.as_str());
            Ok(if let Some(point) = Point::from_be_bytes(&point_bytes) {
                point
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Некорректный публичный ключ"),
                ));
            })
        }).filter(|v| v.is_ok()).map(|v| v.unwrap()).collect();

        Ok(Self {
            public_keys
        })
    }

    pub fn get_public_keys(&self) -> &Vec<Point> {
        &self.public_keys
    }
}