pub enum PointType {
    Matrix,
    List,
    RangeVerificationKey,
    // Bit // BitProve биты не относятся к PointType
}

impl PointType {
    pub fn to_string(&self) -> String {
        String::from(match self {
            Self::Matrix => "matrix",
            Self::List => "list",
            Self::RangeVerificationKey => "range_verification_key",
            // Self::Bit => "bit",
        })
    }
}