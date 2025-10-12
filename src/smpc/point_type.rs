pub enum PointType {
    Matrix,
    List,
}

impl PointType {
    pub fn to_string(&self) -> String {
        String::from(match self {
            Self::Matrix => "matrix",
            Self::List => "list",
        })
    }
}