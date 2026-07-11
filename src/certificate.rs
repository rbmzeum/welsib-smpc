use crate::conv::u2vec::u2vec;
use crate::conv::hex2vec::hex2vec;
use crate::conv::vec2u::vec2u;
use welsib_u512::u512::U512;
use welsib_u512_ec::sign::Signature;
use welsib_u512_ec::point::Point;
use welsib_u512_ec::elliptic_curve::EllipticCurve;
use welsib_json::{JsonValue, from_json, to_json};
use crate::range_prove::BitProve;
use std::collections::BTreeMap;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Certificate {
    // pub matrix_points: Vec<Point>,
    // pub list_points: Vec<Point>,
    // pub bit_proves: BTreeMap<U512, Vec<BitProve>>,
    // pub agg_point: Point,
    // pub agg_point_hash: U512,
    // pub signature: Signature,

    pub h_main: Option<Point>,           // Публичный ключ контролёра
    pub client_h_list: Vec<Point>,       // Список клиентских h-точек
    pub matrix_points: Vec<Point>,       // Точки матрицы (p1)
    pub list_points: Vec<Point>,         // Точки списка (p2)
    pub bit_proves: BTreeMap<U512, Vec<BitProve>>, // Доказательства диапазона
    pub agg_point: Point,                // Агрегированная точка
    // pub agg_point_hash: Vec<u8>,         // Хеш агрегированной точки
    // pub signature: Vec<u8>,              // Подпись контролёра
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

// Структура для сериализации одного BitProve
#[derive(Debug)]
struct BitProveJson {
    t_x: String,
    t_y: String,
    r1: String,
    r2: String,
    diff_x: String,
    diff_y: String,
    c_x: String,
    c_y: String,
    z_x: String,
    z_y: String,
}

impl BitProveJson {
    pub fn from_bit_prove(bit_prove: &BitProve) -> Self {
        Self {
            t_x: u2vec(bit_prove.get_t().x.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            t_y: u2vec(bit_prove.get_t().y.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            r1: u2vec(bit_prove.get_r1().clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            r2: u2vec(bit_prove.get_r2().clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            diff_x: u2vec(bit_prove.get_diff().x.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            diff_y: u2vec(bit_prove.get_diff().y.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            c_x: u2vec(bit_prove.get_c().x.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            c_y: u2vec(bit_prove.get_c().y.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            z_x: u2vec(bit_prove.get_z().x.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            z_y: u2vec(bit_prove.get_z().y.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        }
    }
    
    pub fn to_bit_prove(&self) -> std::io::Result<BitProve> {
        let curve = EllipticCurve::make_curve_welsib();
        
        let t = Point {
            x: vec2u(hex2vec(self.t_x.clone())),
            y: vec2u(hex2vec(self.t_y.clone())),
        };
        
        let r1 = vec2u(hex2vec(self.r1.clone()));
        let r2 = vec2u(hex2vec(self.r2.clone()));
        
        let diff = Point {
            x: vec2u(hex2vec(self.diff_x.clone())),
            y: vec2u(hex2vec(self.diff_y.clone())),
        };
        
        let c = Point {
            x: vec2u(hex2vec(self.c_x.clone())),
            y: vec2u(hex2vec(self.c_y.clone())),
        };
        
        let z = Point {
            x: vec2u(hex2vec(self.z_x.clone())),
            y: vec2u(hex2vec(self.z_y.clone())),
        };
        
        Ok(BitProve::new(t, r1, r2, diff, c, z, curve.g.clone()))
    }
}

impl Certificate {
    pub fn to_string(&self) -> String {
        // h_main section (может быть null)
        let h_main_json = match &self.h_main {
            Some(h_main) => {
                let x = u2vec(h_main.x.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
                let y = u2vec(h_main.y.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
                format!("{{\"x\":\"{x}\",\"y\":\"{y}\"}}")
            }
            None => "null".to_string(),
        };
        
        // client_h_list section
        let client_h_list_jsons: Vec<String> = self.client_h_list.iter().map(|p| {
            let x = u2vec(p.x.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
            let y = u2vec(p.y.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
            String::from(format!("{{\"x\":\"{x}\",\"y\":\"{y}\"}}"))
        }).collect();

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
        
        // bit_proves section - JSON объект, где ключи - hex строки x координат публичных ключей
        let mut bit_proves_obj = HashMap::new();
        for (x_coord, bit_proves_vec) in &self.bit_proves {
            let client_key = u2vec(x_coord.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>();
            
            // Сериализуем каждый BitProve в JSON объект
            let bit_proves_json_array: Vec<String> = bit_proves_vec.iter()
                .map(|bp| {
                    let bp_json = BitProveJson::from_bit_prove(bp);
                    let json_str = format!(
                        "{{\"t_x\":\"{}\",\"t_y\":\"{}\",\"r1\":\"{}\",\"r2\":\"{}\",\"diff_x\":\"{}\",\"diff_y\":\"{}\",\"c_x\":\"{}\",\"c_y\":\"{}\",\"z_x\":\"{}\",\"z_y\":\"{}\"}}",
                        bp_json.t_x, bp_json.t_y, bp_json.r1, bp_json.r2,
                        bp_json.diff_x, bp_json.diff_y, bp_json.c_x, bp_json.c_y,
                        bp_json.z_x, bp_json.z_y
                    );
                    json_str
                })
                .collect();
            
            // Объединяем все JSON строки в одну строку массива
            let bit_proves_array_json = format!("[{}]", bit_proves_json_array.join(","));
            bit_proves_obj.insert(client_key, bit_proves_array_json);
        }
        
        // Преобразуем HashMap в JSON строку
        let bit_proves_json_string = to_json(&JsonValue::Object(
            bit_proves_obj.into_iter()
                .map(|(k, v)| (k, JsonValue::String(v)))
                .collect()
        ));
        
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
            String::from("h_main section"),
            h_main_json,
            String::from("client_h_list section"),
            client_h_list_jsons.join("\n"),
            String::from("matrix_points section"),
            matrix_points_jsons.join("\n"),
            String::from("list_points section"),
            list_points_jsons.join("\n"),
            String::from("bit_proves section"),
            bit_proves_json_string,
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
        let mut h_main = None;
        let mut client_h_list = vec![];
        let mut matrix_points = vec![];
        let mut list_points = vec![];
        let mut bit_proves = BTreeMap::new();
        let mut agg_point = None;
        let mut agg_point_hash = None;
        let mut signature = None;

        let mut status = 0;
        let mut current_bit_proves_json = String::new();
        let mut in_bit_proves_section = false;
        
        for line in lines {
            let new_status = match line.as_str() {
                "*****BEGIN CERTIFICATE*****" => 0,
                "h_main section" => 1,
                "client_h_list section" => 2,
                "matrix_points section" => 3,
                "list_points section" => 4,
                "bit_proves section" => {
                    in_bit_proves_section = true;
                    5
                },
                "agg_point section" => 6,
                "agg_point_hash section" => 7,
                "signature section" => 8,
                "*****END CERTIFICATE*****" => 9,
                _ => status
            };
            
            if status != new_status {
                status = new_status;
                if status != 5 {
                    in_bit_proves_section = false;
                }
                continue;
            }
            
            match status {
                1 => {
                    if line == "null" {
                        h_main = None;
                    } else {
                        let point_json: PointJson = if let Some(point_json) = PointJson::from_str(line.as_str()) {
                            point_json
                        } else {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "Некорректный формат 'h_main section'",
                            ));
                        };
                        let x = vec2u(hex2vec(point_json.x));
                        let y = vec2u(hex2vec(point_json.y));
                        h_main = Some(Point {x, y});
                    }
                },
                2 => {
                    let point_json: PointJson = if let Some(point_json) = PointJson::from_str(line.as_str()) {
                        point_json
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Некорректный формат 'client_h_list section'",
                        ));
                    };
                    let x = vec2u(hex2vec(point_json.x));
                    let y = vec2u(hex2vec(point_json.y));
                    client_h_list.push(Point {x, y});
                },
                3 => {
                    let point_json: PointJson = if let Some(point_json) = PointJson::from_str(line.as_str()) {
                        point_json
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Некорректный формат 'matrix_points section'",
                        ));
                    };
                    let x = vec2u(hex2vec(point_json.x));
                    let y = vec2u(hex2vec(point_json.y));
                    matrix_points.push(Point {x, y});
                },
                4 => {
                    let point_json: PointJson = if let Some(point_json) = PointJson::from_str(line.as_str()) {
                        point_json
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Некорректный формат 'list_points section'",
                        ));
                    };
                    let x = vec2u(hex2vec(point_json.x));
                    let y = vec2u(hex2vec(point_json.y));
                    list_points.push(Point {x, y});
                },
                5 => {
                    // Собираем JSON строку для bit_proves (может быть многострочной)
                    if in_bit_proves_section {
                        current_bit_proves_json.push_str(line);
                    }
                },
                6 => {
                    let point_json: PointJson = if let Some(point_json) = PointJson::from_str(line.as_str()) {
                        point_json
                    } else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Некорректный формат 'agg_point section'",
                        ));
                    };
                    let x = vec2u(hex2vec(point_json.x));
                    let y = vec2u(hex2vec(point_json.y));
                    agg_point = Some(Point {x, y});
                },
                7 => agg_point_hash = Some(hex2vec(line.clone())),
                8 => {
                    // Теперь signature - это просто hex строка с байтами
                    signature = Some(hex2vec(line.clone()));
                },
                _ => {},
            }
        }
        
        // Парсим bit_proves JSON после сбора всей строки
        if !current_bit_proves_json.is_empty() {
            if let Ok(JsonValue::Object(obj)) = from_json(&current_bit_proves_json) {
                for (client_key_hex, bit_proves_array_json) in obj {
                    if let JsonValue::String(array_json_str) = bit_proves_array_json {
                        // Парсим массив BitProve
                        if let Ok(JsonValue::Array(bit_prove_jsons)) = from_json(&array_json_str) {
                            let mut bit_proves_vec = Vec::new();
                            
                            for bp_json_val in bit_prove_jsons {
                                if let JsonValue::String(bp_json_str) = bp_json_val {
                                    // Парсим отдельный BitProve JSON
                                    if let Ok(JsonValue::Object(bp_obj)) = from_json(&bp_json_str) {
                                        let t_x = if let Some(JsonValue::String(t_x)) = bp_obj.get("t_x") {
                                            t_x.clone()
                                        } else {
                                            return Err(std::io::Error::new(
                                                std::io::ErrorKind::InvalidInput,
                                                "Некорректный формат BitProve (t_x)",
                                            ));
                                        };
                                        
                                        let t_y = if let Some(JsonValue::String(t_y)) = bp_obj.get("t_y") {
                                            t_y.clone()
                                        } else {
                                            return Err(std::io::Error::new(
                                                std::io::ErrorKind::InvalidInput,
                                                "Некорректный формат BitProve (t_y)",
                                            ));
                                        };
                                        
                                        // Аналогично для остальных полей...
                                        // Для краткости, создадим BitProveJson и преобразуем
                                        let bp_json = BitProveJson {
                                            t_x: t_x.clone(),
                                            t_y: t_y.clone(),
                                            r1: if let Some(JsonValue::String(r1)) = bp_obj.get("r1") {
                                                r1.clone()
                                            } else {
                                                return Err(std::io::Error::new(
                                                    std::io::ErrorKind::InvalidInput,
                                                    "Некорректный формат BitProve (r1)",
                                                ));
                                            },
                                            r2: if let Some(JsonValue::String(r2)) = bp_obj.get("r2") {
                                                r2.clone()
                                            } else {
                                                return Err(std::io::Error::new(
                                                    std::io::ErrorKind::InvalidInput,
                                                    "Некорректный формат BitProve (r2)",
                                                ));
                                            },
                                            diff_x: if let Some(JsonValue::String(diff_x)) = bp_obj.get("diff_x") {
                                                diff_x.clone()
                                            } else {
                                                return Err(std::io::Error::new(
                                                    std::io::ErrorKind::InvalidInput,
                                                    "Некорректный формат BitProve (diff_x)",
                                                ));
                                            },
                                            diff_y: if let Some(JsonValue::String(diff_y)) = bp_obj.get("diff_y") {
                                                diff_y.clone()
                                            } else {
                                                return Err(std::io::Error::new(
                                                    std::io::ErrorKind::InvalidInput,
                                                    "Некорректный формат BitProve (diff_y)",
                                                ));
                                            },
                                            c_x: if let Some(JsonValue::String(c_x)) = bp_obj.get("c_x") {
                                                c_x.clone()
                                            } else {
                                                return Err(std::io::Error::new(
                                                    std::io::ErrorKind::InvalidInput,
                                                    "Некорректный формат BitProve (c_x)",
                                                ));
                                            },
                                            c_y: if let Some(JsonValue::String(c_y)) = bp_obj.get("c_y") {
                                                c_y.clone()
                                            } else {
                                                return Err(std::io::Error::new(
                                                    std::io::ErrorKind::InvalidInput,
                                                    "Некорректный формат BitProve (c_y)",
                                                ));
                                            },
                                            z_x: if let Some(JsonValue::String(z_x)) = bp_obj.get("z_x") {
                                                z_x.clone()
                                            } else {
                                                return Err(std::io::Error::new(
                                                    std::io::ErrorKind::InvalidInput,
                                                    "Некорректный формат BitProve (z_x)",
                                                ));
                                            },
                                            z_y: if let Some(JsonValue::String(z_y)) = bp_obj.get("z_y") {
                                                z_y.clone()
                                            } else {
                                                return Err(std::io::Error::new(
                                                    std::io::ErrorKind::InvalidInput,
                                                    "Некорректный формат BitProve (z_y)",
                                                ));
                                            },
                                        };
                                        
                                        match bp_json.to_bit_prove() {
                                            Ok(bit_prove) => bit_proves_vec.push(bit_prove),
                                            Err(e) => return Err(e),
                                        }
                                    }
                                }
                            }
                            
                            // Преобразуем hex строку ключа в U512
                            let client_key = vec2u(hex2vec(client_key_hex));
                            bit_proves.insert(client_key, bit_proves_vec);
                        }
                    }
                }
            }
        }

        Ok(Self {
            h_main,
            client_h_list,
            matrix_points,
            list_points,
            bit_proves,
            agg_point: if let Some(agg_point) = agg_point { agg_point } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Некорректный формат 'agg_point section'",
                ));
            },
            agg_point_hash: if let Some(agg_point_hash) = agg_point_hash { vec2u(agg_point_hash) } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Некорректный формат 'agg_point_hash section'",
                ));
            },
            signature: if let Some(signature) = signature { Signature::from_be_bytes(&signature) } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Некорректный формат 'signature section'",
                ));
            },
        })
    }
}