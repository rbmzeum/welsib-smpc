use welsib_u512_ec::keys::welsib_make_signing_key;
use welsib_u512::u512::{U512, U512Shr};

pub fn create_shifted_random() -> U512 {
    let mut wsk = welsib_make_signing_key();
    wsk.shr(16); // изначально стояло 4, но из 512 бит выделить 16 бит, чтобы при суммировании оставить возможность до 65535 клиентов
    wsk
}