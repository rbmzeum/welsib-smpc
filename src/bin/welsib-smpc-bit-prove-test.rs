use welsib_u512_ec::elliptic_curve::EllipticCurve;
use welsib_smpc::range_prove::{bit_prove, bit_verify, BitProveKeys, BitProveSecretKey, BitProvePublicKey};
use welsib_u512_ec::keys::{make_keypair, make_signing_key};

fn main() {
    let curve = EllipticCurve::make_curve_welsib();

    let bit = true; // or false
    let (k, h) = make_keypair(&curve);
    let rr = make_signing_key(&curve);
    let rl = make_signing_key(&curve);
    let keys = BitProveKeys::new(
        BitProveSecretKey::new(k, rr, rl),
        BitProvePublicKey::new(h)
    );
    let bp = bit_prove(&curve, bit, &keys);
    let result = bit_verify(&curve, &bp, keys.get_public_key());
    println!("Result: {:x?}", &result);
}