#[derive(Debug, Clone)]
pub struct WelsibVerifierArguments {
    need_help: bool,
    config_filename: Option<String>,
}

impl WelsibVerifierArguments {
    pub fn init() -> Self {
        let mut need_help = false;
        let mut config = None;

        // let mut domain = None;
        for argument in std::env::args() {
            // Need help
            if argument.eq("--help") || argument.eq("-h") {
                need_help = true;
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
        }
        Self {
            need_help,
            config_filename: config,
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
