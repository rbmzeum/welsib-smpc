use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct WelsibServerArguments {
    need_help: bool,
    is_pub: bool,
    concurrency: usize,
    secret_key_filename: Option<String>,
    config_filename: Option<String>,
    host: String,
    port: String,
}

impl WelsibServerArguments {
    pub fn init() -> Self {
        let mut need_help = false;
        // let mut has_ssl = true;
        // let mut is_dev = false;
        let mut is_pub = false;
        let mut concurrency = 1;
        let mut key = None;
        let mut config = None;
        let mut host = String::from("127.0.0.1");
        let mut port = None;
        // let mut domain = None;
        for argument in std::env::args() {
            // Need help
            if argument.eq("--help") || argument.eq("-h") {
                need_help = true;
            }

            // Public keys for all
            if argument.eq("--pub") {
                is_pub = true;
            }

            // Concurrency
            if argument.starts_with("--concurrency=")  {
                if let Some(c) = argument.get(14..) {
                    if let Ok(c) = usize::from_str(c) {
                        concurrency = c;
                    }
                }
            }

            // Key
            if argument.starts_with("--key=") {
                let k = argument.get(6..);
                match k {
                    Some(k) => {
                        key = Some(String::from(k));
                    }
                    None => {}
                }
            }

            // Config
            if argument.starts_with("--config=") {
                let cfg = argument.get(9..);
                match cfg {
                    Some(cfg) => {
                        config = Some(String::from(cfg));
                    }
                    None => {}
                }
            }

            // Host
            if argument.starts_with("--host=") {
                let h = argument.get(7..);
                match h {
                    Some(h) => {
                        let addr = IpAddr::from_str(h);
                        match addr {
                            Ok(addr) => {
                                if addr.is_ipv4() {
                                    host = String::from(h.trim());
                                }
                            }
                            _ => {
                                // is valid domain name
                                match h.to_socket_addrs() {
                                    Ok(ref mut s) => match s.next() {
                                        Some(_) => {
                                            host = String::from(h.trim());
                                        }
                                        _ => {}
                                    },
                                    _ => {}
                                };
                            }
                        }
                    }
                    None => {}
                }
            }

            // Port
            if argument.starts_with("--port=") {
                let p = argument.get(7..);
                match p {
                    Some(p) => {
                        let p = u16::from_str(p);
                        match p {
                            Ok(p) => {
                                if p > 1023 {
                                    port = Some(p);
                                } else {
                                    // TODO: log warning
                                }
                            }
                            _ => {}
                        }
                    }
                    None => {}
                }
            }
        }
        Self {
            need_help,
            is_pub,
            concurrency,
            host,
            secret_key_filename: key,
            config_filename: config,
            port: match port {
                Some(port) => port.to_string(),
                None => (8555).to_string(),
            },
        }
    }

    pub fn get_addr(&self) -> String {
        self.host.clone() + ":" + &self.port.clone()
    }

    pub fn is_pub(&self) -> bool {
        self.is_pub.clone()
    }

    pub fn get_concurrency(&self) -> usize {
        self.concurrency.clone()
    }

    pub fn get_secret_key_filename(&self) -> std::io::Result<String> {
        match self.secret_key_filename {
            Some(ref file_name) => Ok(file_name.clone()),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Неверно указан аргумент с именем файла секретного ключа",
            )),
        }
    }

    pub fn get_config_filename(&self) -> std::io::Result<String> {
        match self.config_filename {
            Some(ref file_name) => Ok(file_name.clone()),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Неверно указан аргумент с именем файла конфигурации",
            )),
        }
    }

    pub fn need_help(&self) -> bool {
        self.need_help
    }
}
