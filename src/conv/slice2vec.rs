pub fn slice2vec(v64: [u64; 8]) -> Vec<u8> {
    v64.map(|v| v.to_be_bytes()).concat()
}
