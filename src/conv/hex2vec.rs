pub fn hex2vec(data: String) -> Vec<u8> {
    data.as_bytes()
    .chunks(2)
    .map(|b| u8::from_str_radix(&String::from_utf8(b.to_vec()).unwrap(), 16).unwrap())
    .collect::<Vec<u8>>()
}