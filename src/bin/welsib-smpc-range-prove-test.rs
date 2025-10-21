use welsib_u512_ec::elliptic_curve::EllipticCurve;
use welsib_smpc::range_prove::{range_prove, range_verify};

fn main() {
    let curve = EllipticCurve::make_curve_welsib();

    const RANGE: usize = 4;
    let value = 0b1101; // 13

    let k = make_signing_key(&curve).unwrap();
    if let Some((c_keys, c_points, confidential_value)) = range_prove(&curve, value, RANGE, &k) { // Вызывается на стороне доказывающего
        let result = range_verify(&curve, &c_points, RANGE, confidential_value); // Вызывается на сторое проверяющего (в отдельности не привязан к value)
        println!("Sulution: {:?}", &result);
    } else {
        println!("Value out of range");
    };

    // TODO: собрать Point из value, не побитово (добавить ключ к value, чтобы не позволить брутфорсом выяснить малое значение value)
    // v = (rr0*2^0 + rr1*2^1 + rr2*2^2 + ... + rr127*2^127) * k + value
    // P(v) = (rr0 + rr1<<1 + rr2<<2 + ... + rr127<<127)*H + value*G
    // r_v = rr0 + rr1<<1 + rr2<<2 + ... + rr127<<127

    // TODO: при объединении с WSMPC создать возможность сопоставить значение P(v) с ключами из WSMPC
    // (осторожно, не создать возможность брутфорса поинтов для value)

    // TODO: исследовать возможность сжать список Point-ов "c" в один Point "c_agg"
    // c_agg / 2^i (не понятно как выполнить операцию битового "И" для Point)
}