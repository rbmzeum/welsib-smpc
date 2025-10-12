use welsib_u512::u512::U512;

pub fn vec2u(data: Vec<u8>) -> U512 {
    let mut bytes: [u8; 64] = [0; 64];
    bytes.clone_from_slice(&data);
    U512::from_be_bytes(&bytes)
}
