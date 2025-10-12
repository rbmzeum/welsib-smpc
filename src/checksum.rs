use welsib_u512_ec::hash::whash;

pub fn crc32(bytes: &Vec<u8>) -> u32 {
    let wh = whash(bytes);
    u32::from_be_bytes([wh[0], wh[1], wh[2], wh[3]])
}
