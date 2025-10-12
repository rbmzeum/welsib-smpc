use crate::conv::u2vec::u2vec;
use crate::conv::hex2vec::hex2vec;
use crate::conv::vec2u::vec2u;
use welsib_u512::u512::U512;
use welsib_u512_ec::sign::Signature;
use welsib_u512_ec::point::Point;
use welsib_json::{JsonValue, from_json, to_json};

#[derive(Debug)]
pub struct Certificate {
    pub matrix_points: Vec<Point>,
    pub list_points: Vec<Point>,
    pub agg_point: Point,
    pub agg_point_hash: U512,
    pub signature: Signature,
}

struct PointJson {
    x: String,
    y: String,
}

impl PointJson {
    pub fn from_str(json: &str) -> Option<Self> {
        if let JsonValue::Object(obj) = from_json(json).unwrap() {
            let x = if let Some(JsonValue::String(x)) = obj.get("x") {
                x.clone()
            } else {
                return None;
            };

            let y = if let Some(JsonValue::String(y)) = obj.get("y") {
                y.clone()
            } else {
                return None;
            };

            Some(Self {x, y})
        } else {
            None
        }
    }
}

struct SignatureJson {
    r: String,
    s: String,
}

impl SignatureJson {
    pub fn from_str(json: &str) -> Option<Self> {
        if let JsonValue::Object(obj) = from_json(json).unwrap() {
            let r = if let Some(JsonValue::String(r)) = obj.get("r") {
                r.clone()
            } else {
                return None;
            };

            let s = if let Some(JsonValue::String(s)) = obj.get("s") {
                s.clone()
            } else {
                return None;
            };

            Some(Self {r, s})
        } else {
            None
        }
    }
}

impl Certificate {
    pub fn to_string(&self) -> String {
        // matrix_points section
        let matrix_points_jsons: Vec<String> = self.matrix_points.iter().map(|p| {
            let x = u2vec(p.x.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
            let y = u2vec(p.y.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
            String::from(format!("{{\"x\":\"{x}\",\"y\":\"{y}\"}}"))
        }).collect();
        // list_points section
        let list_points_jsons: Vec<String> = self.list_points.iter().map(|p| {
            let x = u2vec(p.x.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
            let y = u2vec(p.y.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
            String::from(format!("{{\"x\":\"{x}\",\"y\":\"{y}\"}}"))
        }).collect();
        // agg_point section
        let x = u2vec(self.agg_point.x.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let y = u2vec(self.agg_point.y.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let agg_point_json = String::from(format!("{{\"x\":\"{x}\",\"y\":\"{y}\"}}"));
        // agg_point_hash section
        let agg_point_hash_string = u2vec(self.agg_point_hash.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
        // signature section
        let r = u2vec(self.signature.r.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let s = u2vec(self.signature.s.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let signature_json = String::from(format!("{{\"r\":\"{r}\",\"s\":\"{s}\"}}"));

        [
            String::from("*****BEGIN CERTIFICATE*****"),
            String::from("matrix_points section"),
            matrix_points_jsons.join("\n"),
            String::from("list_points section"),
            list_points_jsons.join("\n"),
            String::from("agg_point section"),
            agg_point_json,
            String::from("agg_point_hash section"),
            agg_point_hash_string,
            String::from("signature section"),
            signature_json,
            String::from("*****END CERTIFICATE*****"),
        ].join("\n")
    }

    pub fn from_lines(lines: &Vec<String>) -> std::io::Result<Self> {
        let mut matrix_points = vec![];
        let mut list_points = vec![];
        let mut agg_point = None;
        let mut agg_point_hash = None;
        let mut signature = None;

        let mut status = 0;
        for line in lines {
            let new_status = match line.as_str() {
                "*****BEGIN CERTIFICATE*****" => 0,
                "matrix_points section" => 1,
                "list_points section" => 2,
                "agg_point section" => 3,
                "agg_point_hash section" => 4,
                "signature section" => 5,
                "*****END CERTIFICATE*****" => 6,
                _ => status
            };
            if status != new_status {
                status = new_status;
                continue;
            }
            match status {
                1 => {
                    let point_json: PointJson = if let Some(point_json) = PointJson::from_str(line.as_str()) {
                        point_json
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Некорретный формат 'matrix_points section'",
                        ));
                    };
                    let x = vec2u(hex2vec(point_json.x));
                    let y = vec2u(hex2vec(point_json.y));
                    matrix_points.push(Point {x, y});
                },
                2 => {
                    let point_json: PointJson = if let Some(point_json) = PointJson::from_str(line.as_str()) {
                        point_json
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Некорретный формат 'list_points section'",
                        ));
                    };
                    let x = vec2u(hex2vec(point_json.x));
                    let y = vec2u(hex2vec(point_json.y));
                    list_points.push(Point {x, y});
                },
                3 => {
                    let point_json: PointJson = if let Some(point_json) = PointJson::from_str(line.as_str()) {
                        point_json
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Некорретный формат 'agg_point section'",
                        ));
                    };
                    let x = vec2u(hex2vec(point_json.x));
                    let y = vec2u(hex2vec(point_json.y));
                    agg_point = Some(Point {x, y});
                },
                4 => agg_point_hash = Some(vec2u(hex2vec(line.clone()))),
                5 => {
                    let signature_json: SignatureJson = if let Some(signature_json) = SignatureJson::from_str(line.as_str()) {
                        signature_json
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Некорретный формат 'signature section'",
                        ));
                    };
                    let r = vec2u(hex2vec(signature_json.r));
                    let s = vec2u(hex2vec(signature_json.s));
                    signature = Some(Signature {r, s});
                },
                _ => {},
            }
        }

        Ok(Self {
            matrix_points,
            list_points,
            agg_point: if let Some(agg_point) = agg_point { agg_point } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Некорретный формат 'agg_point section'",
                ));
            },
            agg_point_hash: if let Some(agg_point_hash) = agg_point_hash { agg_point_hash } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Некорретный формат 'agg_point_hash section'",
                ));
            },
            signature: if let Some(signature) = signature { signature } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Некорретный формат 'signature section'",
                ));
            },
        })
    }
}