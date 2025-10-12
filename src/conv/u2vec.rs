use welsib_u512::u512::U512;

pub fn u2vec(x: U512) -> Vec<u8> {
    x.to_be_bytes().to_vec()
}
