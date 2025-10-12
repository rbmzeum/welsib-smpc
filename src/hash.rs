use welsib_u512_ec::hash::whash;
use welsib_u512::u512::U512;

pub fn hash(bytes: &[u8]) -> U512 {
    U512::from_be_bytes(&whash(bytes))
}