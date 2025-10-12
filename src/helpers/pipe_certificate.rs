#[derive(Debug, Clone)]
pub struct StdInCertificate {
    pub lines: Vec<String>,
}

impl StdInCertificate {
    pub fn read() -> std::io::Result<Self> {
        let mut lines = vec![];

        for line in std::io::stdin().lines() {
            if let Ok(line) = line {
                lines.push(line);
            }
        }

        Ok(Self {
            lines
        })
    }
}
