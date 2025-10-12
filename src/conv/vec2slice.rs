pub fn vec2slice(v8: Vec<u8>) -> [u64; 8] {
    // FIXME: сделать без выделения дополнительной памяти и копирования
    let mut result: [u64; 8] = [0; 8];
    let v64 = v8
        .chunks(8)
        .map(|v| u64::from_be_bytes(v.try_into().unwrap()))
        .collect::<Vec<u64>>();
    result.clone_from_slice(&v64);
    result
}
