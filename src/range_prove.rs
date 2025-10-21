use std::collections::BTreeMap;
use std::ops::Shr;
use welsib_u512::u512::{U512, U512Shr, U1024, shl1024};
use welsib_u512_ec::keys::{make_verifying_key, make_signing_key};
use welsib_u512_ec::elliptic_curve::x2_mod::x2_mod;
use welsib_u512_ec::point::Point;
use crate::random::create_random_additive_parts;
use welsib_u512_ec::keys::make_keypair;
use welsib_u512_ec::elliptic_curve::EllipticCurve;
use welsib_u512_ec::sign::EllipticCurveSign;
use welsib_u512_ec::hash::whash;
use welsib_u512_ec::elliptic_curve::mul_mod::mul_mod;
use welsib_u512_ec::elliptic_curve::add_mod::add_mod;
use welsib_u512_ec::elliptic_curve::sub_mod::sub_mod;
use welsib_u512_ec::elliptic_curve::rem_inv::rem_inv;

#[derive(Debug, Clone)]
pub struct BitProve {
    t: Point,
    r1: U512,
    r2: U512,
    diff: Point,
    c: Point,
    z: Point,
    g: Point
}

impl BitProve {
    fn new(t: Point, r1: U512, r2: U512, diff: Point, c: Point, z: Point, g: Point) -> Self {
        Self { t, r1, r2, diff, c, z, g }
    }

    fn get_t(&self) -> &Point {
        &self.t
    }

    fn get_r1(&self) -> &U512 {
        &self.r1
    }

    fn get_r2(&self) -> &U512 {
        &self.r2
    }

    fn get_diff(&self) -> &Point {
        &self.diff
    }

    fn get_c(&self) -> &Point {
        &self.c
    }

    fn get_z(&self) -> &Point {
        &self.z
    }

    fn get_g(&self) -> &Point {
        &self.g
    }
}

#[derive(Debug, Clone)]
pub struct BitProveSecretKey {
    k: U512,
    rr: U512,
    rl: U512,
}

impl BitProveSecretKey {
    pub fn new(k: U512, rr: U512, rl: U512) -> Self {
        Self { k, rr, rl }
    }

    pub fn get_k(&self) -> U512 {
        self.k
    }

    pub fn get_rr(&self) -> U512 {
        self.rr
    }

    pub fn get_rl(&self) -> U512 {
        self.rl
    }
}

#[derive(Debug, Clone)]
pub struct BitProvePublicKey {
    h: Point
}

impl BitProvePublicKey {
    pub fn new(h: Point) -> Self {
        Self { h }
    }

    pub fn get_h(&self) -> &Point {
        &self.h
    }
}

#[derive(Debug, Clone)]
pub struct BitProveKeys {
    secret_key: BitProveSecretKey,
    public_key: BitProvePublicKey
}

impl BitProveKeys {
    pub fn new(secret_key: BitProveSecretKey, public_key: BitProvePublicKey) -> Self {
        Self {
            secret_key,
            public_key
        }
    }

    pub fn get_secret_key(&self) -> &BitProveSecretKey {
        &self.secret_key
    }

    pub fn get_public_key(&self) -> &BitProvePublicKey {
        &self.public_key
    }
}

pub fn bit_prove(curve: &EllipticCurve, bit: bool, keys: &BitProveKeys) -> BitProve {
    let k = keys.get_secret_key().get_k();
    let h = keys.get_public_key().get_h();
    let rr = keys.get_secret_key().get_rr();
    let rl = keys.get_secret_key().get_rl();
    let c = if bit {
        // P(rr*k+1)
        curve.add_point(&curve.multiply(&rr, &h).unwrap(), &curve.g).unwrap()
    } else {
        // P(rr*k)
        curve.multiply(&rr, &h).unwrap()
    };
    let z = if bit {
        curve.multiply(&rl, &h).unwrap()
    } else {
        curve.sub_point(&curve.multiply(&rl, &h).unwrap(), &curve.g).unwrap()
    };
    let x = sub_mod(&rr, &rl, &curve.q);
    let y = if bit { U512::one() } else { sub_mod(&U512::zero(), &U512::one(), &curve.q) };
    let diff = curve.multiply(&mul_mod(&x, &k, &curve.q).unwrap(), &curve.g).unwrap();
    let d1 = make_signing_key(curve);
    let d2 = make_signing_key(curve);
    let t = curve.multiply(&add_mod(&mul_mod(&d1, &k, &curve.q).unwrap(), &d2, &curve.q).unwrap(), &curve.g).unwrap();
    let hash = whash(&vec![
        t.to_be_bytes().to_vec(),
        c.to_be_bytes().to_vec(),
        z.to_be_bytes().to_vec(),
        diff.to_be_bytes().to_vec(),
        curve.g.to_be_bytes().to_vec(),
        h.to_be_bytes().to_vec()
    ].concat());
    let e = (U1024::new_from_u512(&U512::from_be_bytes(&hash)) % &curve.q).unwrap();
    // r1 = d1 + e * x 
    let r1 = add_mod(&d1, &mul_mod(&e, &x, &curve.q).unwrap(), &curve.q).unwrap();
    let r1v1 = add_mod(&r1, &mul_mod(&e, &rem_inv(&k, &curve.q).unwrap(), &curve.q).unwrap(), &curve.q).unwrap();
    let r1v2 = sub_mod(&r1, &mul_mod(&e, &rem_inv(&k, &curve.q).unwrap(), &curve.q).unwrap(), &curve.q);
    // r2 = d2 + e * y
    let r2 = add_mod(&d2, &mul_mod(&e, &y, &curve.q).unwrap(), &curve.q).unwrap();
    BitProve::new(t, if bit { r1v2 } else { r1v1 }, r2, diff, c, z, curve.g.clone())
}

pub fn bit_verify(curve: &EllipticCurve, bp: &BitProve, public_key: &BitProvePublicKey) -> bool {
    let c = bp.get_c();
    let z = bp.get_z();
    let g = bp.get_g();
    let computed_diff = curve.sub_point(&curve.sub_point(c, z).unwrap(), g).unwrap();
    if computed_diff.x != bp.get_diff().x {
        return false;
    }
    let r1 = bp.get_r1();
    let r2 = bp.get_r2();
    let h = public_key.get_h();
    let g = bp.get_g();
    if g.x != curve.g.x {
        return false;
    }
    // r1*H+r2*G == T+e*P(diff)
    let r1h = curve.multiply(r1, h).unwrap();
    let r2g = curve.multiply(r2, g).unwrap();
    let left_side = curve.add_point(&r1h, &r2g).unwrap();
    // println!("Left side:\n{:x?}", &left_side);
    let t = bp.get_t();
    let hash = whash(&vec![
        t.to_be_bytes().to_vec(),
        c.to_be_bytes().to_vec(),
        z.to_be_bytes().to_vec(),
        computed_diff.to_be_bytes().to_vec(),
        g.to_be_bytes().to_vec(),
        h.to_be_bytes().to_vec()
    ].concat());
    let e = (U1024::new_from_u512(&U512::from_be_bytes(&hash)) % &curve.q).unwrap();

    let right_side = curve.add_point(t, &curve.multiply(&e, &computed_diff).unwrap()).unwrap();
    // println!("Right side:\n{:x?}", &right_side);

    left_side == right_side
}

pub fn range_prove(curve: &EllipticCurve, value: u128, range: usize, k: &U512) -> Option<(Vec<U512>, Vec<Point>, Point)> {
    let mut c_keys = vec![];
    let mut c_points = vec![];
    let h = make_verifying_key(curve, k).unwrap();
    if value >> range > 0 && range != 128 { // При range == 128 используется весь range типа u128 (формируется доказательства для всего 128 битного RANGE)
        return None;
    }
    for i in 0..range {
        let bit = (value >> i & 1) != 0;
        let rr = make_signing_key(&curve);
        let rl = make_signing_key(&curve);
        let keys = BitProveKeys::new(
            BitProveSecretKey::new(k.clone(), rr, rl),
            BitProvePublicKey::new(h.clone())
        );
        let bp = bit_prove(&curve, bit, &keys);
        let result = bit_verify(&curve, &bp, keys.get_public_key());
        // println!("Result: bit {i} {:x?}", &result);

        let sk = keys.get_secret_key();
        c_keys.push(sk.get_rr().clone());
        c_points.push(bp.get_c().clone());
    }

    let mut value_left_side_parts = vec![];
    for (i, &rr) in c_keys.iter().enumerate() {
        // let bit = (value >> i & 1) != 0;
        // let c = &c_points[i];
        // println!("\n*****\nItem {i}, {bit}:\n{:016x?}\n{:016x?}\n", &rr, &k);
        if i == 0 {
            // Private:
            // P(c_i) = P(rr*k+b)*2^i
            value_left_side_parts.push(
                curve.multiply(
                    &add_mod(&mul_mod(&rr, k, &curve.q).unwrap(), &U512::from_u64((value & 1) as u64), &curve.q).unwrap(),
                    &curve.g
                ).unwrap()
            );
        } else {
            // Private:
            // P(c_i) = P(rr*k+b)*2^i
            value_left_side_parts.push(
                curve.multiply(
                    &U512::from_u64(1 << i),
                    &curve.multiply(
                        &add_mod(&mul_mod(&rr, k, &curve.q).unwrap(), &U512::from_u64((value >> i & 1) as u64), &curve.q).unwrap(),
                        &curve.g
                    ).unwrap()
                ).unwrap()
            );
        }
    }

    let confidential_value = curve.point_sum(value_left_side_parts).unwrap();

    // Доказывающий RANGE может вычислить confidential_value из c_points и обмануть проверяющего, поэтому в отдельности не используется
    // Используется совместно с доказательством чего-либо другого, где используется value вместе с доказательством RANGE

    Some((c_keys, c_points, confidential_value))
}

pub fn range_verify(curve: &EllipticCurve, c_points: &Vec<Point>, range: usize, value_left_side: Point) -> bool {
    if range < c_points.len() {
        return false;
    }
    let mut value_right_side_parts = vec![];
    for (i, c) in c_points.iter().enumerate() {
        if i == 0 {
            // Public:
            // P(c_i) = c*2^i
            value_right_side_parts.push(
                c.clone()
            );
        } else {
            // Public:
            // P(c_i) = c*2^i
            value_right_side_parts.push(
                curve.multiply(
                    &U512::from_u64(1 << i),
                    c
                ).unwrap()
            );
        }
    }

    let value_right_side = curve.point_sum(value_right_side_parts).unwrap();

    // println!("Value point sum:\n{:x?}\n{:x?}\n{:?}", &value_left_side, &value_right_side, value_left_side == value_right_side);

    value_left_side == value_right_side
}

// Создаёт часть: rr0 + rr1<<1 + rr2<<2+...+rr127<<127
// Из P(rr_v) = P(k*(rr0 + rr1<<1 + rr2<<2+...+rr127<<127)+value)
pub fn rr_i(c_keys: &Vec<U512>, curve_q: &U512) -> U512 {
    let mut v = vec![];
    for (i, &rr) in c_keys.iter().enumerate() {
        v.push(if i == 0 {
            // v[0] = rr*2^0 = rr*1 = rr
            rr.clone()
        } else {
            // v[i] == rr*2^i = rr*(1<<i)
            mul_mod(&rr, &U512::from_u64(1 << i), curve_q).unwrap()
        });
    }

    let mut s = U512::zero();
    for i in 0..v.len() {
        s = add_mod(&s, &v[i], curve_q).unwrap();
    }
    s
}