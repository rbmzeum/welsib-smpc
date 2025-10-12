use crate::certificate::Certificate;
use crate::helpers::arg_conf::Config;
use crate::helpers::pipe_certificate::StdInCertificate;
use welsib_u512_ec::sign::welsib_point_sum;
use welsib_u512_ec::verify::welsib_verify;
use welsib_u512_ec::hash::whash;
use welsib_u512_ec::point::Point;
use welsib_u512::u512::U512;

pub mod print_help;
pub mod arguments;

pub struct Verifier {
    certificate: Certificate,
    verify_key: Point,
}

impl Verifier {
    pub fn new(config: &Config, stdin_certificate: &StdInCertificate)  -> std::io::Result<Self> {
        let verify_key = if let Some(verify_key) = config.get_public_keys().last() {
            verify_key.clone()
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Некорретный формат конфигурационного файла",
            ));
        };

        let certificate = Certificate::from_lines(&stdin_certificate.lines)?;

        Ok(Self {
            certificate,
            verify_key,
        })
    }

    pub fn run(&mut self) -> std::io::Result<(bool, bool, bool, bool)> {
        // 1. Проверить matrix_point_agg == agg_point
        let matrix_point_agg = if let Some(matrix_point_agg) = welsib_point_sum(self.certificate.matrix_points.clone()) { matrix_point_agg } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Некорретный формат certificate.matrix_points",
            ));
        };
        let is_verified_matrix_agg_points = self.certificate.agg_point == matrix_point_agg;
        // 2. Проверить list_point_agg == agg_point
        let list_point_agg = if let Some(list_point_agg) = welsib_point_sum(self.certificate.list_points.clone()) { list_point_agg } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Некорретный формат certificate.list_points",
            ));
        };
        let is_verified_list_agg_points = self.certificate.agg_point == list_point_agg;
        // 3. Проверить hash(agg_point) == agg_point_hash
        let is_verified_agg_point_hash = U512::from_be_bytes(&whash(&self.certificate.agg_point.to_be_bytes())) == self.certificate.agg_point_hash;
        // 4. verify(agg_point_hash, signature, verifier_key)
        let is_verified_signature = welsib_verify(&self.certificate.agg_point_hash, &self.certificate.signature, &self.verify_key);

        Ok((is_verified_matrix_agg_points, is_verified_list_agg_points, is_verified_agg_point_hash, is_verified_signature))
    }
}
