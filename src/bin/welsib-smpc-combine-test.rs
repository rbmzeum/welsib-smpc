use welsib_smpc::server::smpc_field::SMPCField;
use welsib_smpc::smpc::slot::Slot;
use std::collections::BTreeMap;
use std::ops::Shr;
use welsib_u512::u512::{U512, U512Shr};
use welsib_u512_ec::keys::{make_verifying_key, make_signing_key};
use welsib_u512_ec::elliptic_curve::x2_mod::x2_mod;
use welsib_u512_ec::point::Point;
use welsib_smpc::random::create_random_additive_parts;
use welsib_u512_ec::keys::make_keypair;
use welsib_u512_ec::elliptic_curve::EllipticCurve;
use welsib_u512_ec::sign::EllipticCurveSign;

use welsib_smpc::range_prove::{range_prove, range_verify, range_point_from_bits};
use welsib_u512_ec::elliptic_curve::add_mod::add_mod;
use welsib_u512_ec::elliptic_curve::sub_mod::sub_mod;
use welsib_u512_ec::elliptic_curve::mul_mod::mul_mod;
use welsib_smpc::range_prove::rr_i;

fn main() {
    let curve = EllipticCurve::make_curve_welsib();
    // ===========
    let mut smpc_field = SMPCField::new();
    // ===========

    // Конфеденциальные многосторонние вычисления (SMPC "Secure Multi-Party Computation")
    // Альтернативные сценарии

    // Корпоративный аудит:
    // Проверка соответствия общего бюджета компании сумме бюджетов подразделений без раскрытия деталей по отделам.

    // Медицинская статистика:
    // Агрегация данных о заболеваемости из разных больниц для исследований без передачи персональных данных пациентов.

    // Краудфандинг:
    // Верификация общей собранной суммы при сохранении анонимности вкладчиков.

    // Цепочки поставок:
    // Подтверждение общего объема поставок между участниками без раскрытия коммерческой тайны.

    // Кросс-банковское взаимодействие:
    // При переводе средств между банками токен доказывает, что общая сумма на счетах клиента не изменилась.

    let create_random = || {
        let mut key = make_signing_key(&curve);
        // key.shr(4);
        key
    };

    // N == A+B+C+D || S(N) == S(A)+S(B)+S(C)+S(B)
    // Доказательство верности равенства y == x1 + x2 + ... + xn без разглашения y, x1, x2, ..., xn (не 100%, зависит от криптостойкости параметров эллиптической кривой)

    // Банки и налоговая, каждый на своей стороне, генерируют случайные большие числа (секреты), от 0 до curve.q - u64::MAX_VALUE * n(банков)
    // ((((10000*10000*512*5)/8)/1024)/1024)/1024= порядка 30 гигабайт в оперативной памяти будет занимать матрица при PARTS = 10000 (участников)
    const PARTS: usize = 3; // 1 - банк1, 2 - банк2, 3 - налоговая (4 - проверяющий, отдельно)
    const RANGE: usize = 128; // 128 младших значимых бит value

    // Подготовка ключей для шифрования
    let (ctrl_secret_key, ctrl_public_key) = make_keypair(&curve); // Ключи контролёра (аудитора)
    let (sum_secret_key, sum_public_key) = make_keypair(&curve); // Ключи налоговой
    let (part1_secret_key, part1_public_key) = make_keypair(&curve); // Ключи банка 1
    let (part2_secret_key, part2_public_key) = make_keypair(&curve); // Ключи банка 2

    // Симуляция списков ключей загруженных из конфигурационных файлов участников
    let public_keys = [
        &part1_public_key, // 0
        &part2_public_key, // 1
        &sum_public_key, // 2=PARTS-1
        &ctrl_public_key, // 3=PARTS
    ];

    // Дополнительные ключи (протокол обмена частичными ключами)
    // Ключи для интеграции с доказательством диапазона:
    //                  X1    X2     Y
    // X1: kx1 = 604 = 345 + 108 + 151
    // X2: kx2 = 500 = 122 + 263 + 115
    //  Y:  ky = 948 = 233 + 310 + 405
    //  C:  kc = 541 = 244 + 159 + 138
    let kx1_secret = create_random();
    let kx2_secret = create_random();
    let ky_secret = create_random();
    let kc_secret = create_random();
    let kx1_parts = create_random_additive_parts(&kx1_secret, PARTS).unwrap();
    let kx2_parts = create_random_additive_parts(&kx2_secret, PARTS).unwrap();
    let ky_parts = create_random_additive_parts(&ky_secret, PARTS).unwrap();
    let kc_parts = create_random_additive_parts(&kc_secret, PARTS).unwrap();
    let matrix_keys = vec![
        kx1_parts, // 345, 108, 151
        kx2_parts, // 122, 263, 115
        ky_parts,  // 233, 310, 405
        kc_parts   // 244, 159, 138
    ];

    // Шифрование слотов и перераспределение между клиентами
    let mut kx1_slots = vec![];
    let mut kx2_slots = vec![];
    let mut ky_slots = vec![];
    let mut kc_slots = vec![];

    // Реализуется сетевой обмен

    // Клиент 1 (X1 -- часть суммы): public_keys[0]
    let id = 0; // собственный id клиента
    for i in 0..PARTS { // Каждый клиент у себя шифрует слот ключём соответствующего клиента
        let slot = Slot::encrypt(&matrix_keys[id][i], &public_keys[i]);
        // smpc_field.set_client_key_slot(public_keys[id].clone(), i, slot.clone());
        kx1_slots.push(slot);
    }

    // Клиент 2 (X2 -- часть суммы): public_keys[1]
    let id = 1; // собственный id клиента
    for i in 0..PARTS { // Каждый клиент у себя шифрует слот ключём соответствующего клиента
        let slot = Slot::encrypt(&matrix_keys[id][i], &public_keys[i]);
        // smpc_field.set_client_key_slot(public_keys[id].clone(), i, slot.clone());
        kx2_slots.push(slot);
    }

    // Клиент 3 (Y -- сумма): public_keys[1]
    let id = 2; // собственный id клиента
    for i in 0..PARTS { // Каждый клиент у себя шифрует слот ключём соответствующего клиента
        let slot = Slot::encrypt(&matrix_keys[id][i], &public_keys[i]);
        // smpc_field.set_client_key_slot(public_keys[id].clone(), i, slot.clone());
        ky_slots.push(slot);
    }

    // Клиент 4 (C -- контролёр): public_keys[1]
    let id = 3; // собственный id клиента
    // let mut j = 0;
    for i in 0..PARTS { // Каждый клиент у себя шифрует слот ключём соответствующего клиента
        let slot = Slot::encrypt(&matrix_keys[id][i], &public_keys[i]);
        // smpc_field.set_client_key_slot(public_keys[id].clone(), i, slot.clone());
        kc_slots.push(slot);
    }

    // Каждый клиент после сетевого обмена агрегирует полученные данные и создаёт ключи
    let id = 0; // Клиент X1
    let x1_agg_secret_key = curve.u512_sum(vec![
        kx1_slots[id].decrypt(&part1_secret_key),
        kx2_slots[id].decrypt(&part1_secret_key),
        ky_slots[id].decrypt(&part1_secret_key),
        kc_slots[id].decrypt(&part1_secret_key)
    ]);

    let id = 1; // Клиент X2
    let x2_agg_secret_key = curve.u512_sum(vec![
        kx1_slots[id].decrypt(&part2_secret_key),
        kx2_slots[id].decrypt(&part2_secret_key),
        ky_slots[id].decrypt(&part2_secret_key),
        kc_slots[id].decrypt(&part2_secret_key)
    ]);
    let x_agg_secret_keys = vec![x1_agg_secret_key, x2_agg_secret_key];

    let id = 2; // Клиент Y
    let y_agg_secret_key = curve.u512_sum(vec![
        kx1_slots[id].decrypt(&sum_secret_key),
        kx2_slots[id].decrypt(&sum_secret_key),
        ky_slots[id].decrypt(&sum_secret_key),
        kc_slots[id].decrypt(&sum_secret_key)
    ]);

    // Запланировано (с дополнительным ключём для соединения доказательств с сохранением конфиденциальности):
    // r1 = x1_agg_secret_key = 345 + 122 + 233 + 244
    // r2 = x2_agg_secret_key = 108 + 263 + 310 + 159
    // r3 =  y_agg_secret_key = 151 + 115 + 405 + 138
    // matrix:
    // X1 = [[140 + 103]*[345 + 122 + 233 + 244]] + [340 +  49] = 229781 =     0 + 85345 + 51345 + 93091
    // X2 = [[ 30 + 226]*[108 + 263 + 310 + 159]] + [158 +  51] = 215249 = 95234 +     0 + 63234 + 56781
    //  Y = [[ 72 + 151]*[151 + 115 + 405 + 138]] + [480 + 100] = 180987 = 72745 + 45790 +     0 + 62452

    // X1 = [[i + a]*r1] + [    u +   x] = x1m1 + x1m2 + x1m3 + x1m4
    // X2 = [[j + b]*r2] + [    v +   y] = x2m1 + x2m2 + x2m3 + x2m4
    //  Y = [[k + c]*r3] + [a+b+c + x+y] =  ym1 +  ym2 +  ym3 +  ym4

    // Контролёр (аудитор)
    // Каждая часть выходных значений rc[i] шифруется ключём соответствующего участника-приёмщика значения
    let (rc, rc_secret) = {
        // TODO: обнулять левые 4 бита у 512 битных create_random, и сделать count u16, вместо usize для PARTS (MAX 10000, матрица 10к на 10к элементов)
        let rc = create_random(); // rc: 242
        smpc_field.set_random_control_sum_debug(rc.clone());
        // let rc = BigInt::from(242);
        // (vec![140,30,72]).iter().map(|v| BigInt::from(v.clone())).collect::<Vec<_>>()
        let parts = create_random_additive_parts(&rc, PARTS).unwrap(); // rc: 242=[140,30,72].sum()
        smpc_field.set_random_control_values_debug(parts.clone());
        let mut output = vec![];
        for (i, value) in parts.iter().enumerate() {
            let slot = Slot::encrypt(value, &public_keys[i]);
            smpc_field.set_random_control_slot(public_keys[i].clone(), slot.clone());
            output.push(slot);
        }
        (output, parts[PARTS-1].clone())
    };

    // Налоговая
    // Каждая часть rv0[i] и rvy[i] шифруется ключём соответствующего участника-приёмщика значения
    let (rvy, rv0, rvyp, rvy_c_points) = {
        let y: u64 = 100; // Сумма задекларированная пользователем U в налоговую с которой уплачивается налог за определённый год Y

        /////////////////////////////////////////////////////////
        // ry вычисляется из доказательства диапазона range_prove
        let (c_keys, c_points, confidential_value) = range_prove(&curve, y as u128, RANGE, &y_agg_secret_key).unwrap();
        // TODO: валидировать c_points относительно ry_confidential_value: range_verify()
        // Сокрытие value от брутфорса ключём k и ключами rri из доказательства RANGE
        // 480 = (rr0 + rr1<<1 + rr2<<2+...+rr127<<127)*k
        // P(480+100) = P(k*(rr0 + rr1<<1 + rr2<<2+...+rr127<<127)+value)
        let ry = mul_mod(&rr_i(&c_keys, &curve.q), &y_agg_secret_key, &curve.q).unwrap(); // 480
        assert!(range_verify(&curve, &c_points, RANGE, make_verifying_key(&curve, &add_mod(&ry, &U512::from_u64(y.clone()), &curve.q).unwrap()).unwrap()));
        /////////////////////////////////////////////////////////

        // let ry = create_random(); // ry: 480
        // let ry = BigInt::from(480);
        let rv0_parts = create_random_additive_parts(&ry, PARTS).unwrap(); // rv0: 480=[103,226,151].sum() // a+b+c
        let mut rv0 = vec![];
        let mut j = 0;
        for (i, value) in rv0_parts.iter().enumerate() {
            if i == PARTS-1 { j = 1; } // игнорировать диагональный элемент матрицы, и перейти к следующему публичному ключу
            let slot = Slot::encrypt(value, &public_keys[i+j]);
            smpc_field.set_main_client_slot(public_keys[i+j].clone(), slot.clone());
            rv0.push(slot);
        }

        // let rvy_parts = create_random_additive_parts(&(curve.u512_sum([rc[PARTS-1].decrypt(&sum_secret_key), rv0_parts[PARTS-1], ry, U512::from_u64(y)].to_vec())), PARTS).unwrap(); // rvy: 72+151+480+100=803=[295,148,360].sum()
        let rvy_parts = create_random_additive_parts(&(curve.u512_sum([
            mul_mod(&add_mod(&rc[PARTS-1].decrypt(&sum_secret_key), &rv0_parts[PARTS-1], &curve.q).unwrap(), &y_agg_secret_key, &curve.q).unwrap(),
            add_mod(&ry, &U512::from_u64(y), &curve.q).unwrap()
        ].to_vec())), PARTS).unwrap(); // Y: [[72 + 151]*[151 + 115 + 405 + 138]] + [480 + 100]

        let mut rvy = vec![];
        let mut j = 0;
        for (i, value) in rvy_parts.iter().enumerate() {
            if i == PARTS-1 { j = 1; } // игнорировать диагональный элемент матрицы, и перейти к следующему публичному ключу
            let slot = Slot::encrypt(value, &public_keys[i+j]);
            smpc_field.set_client_slot(sum_public_key.clone(), i+j, slot.clone());
            rvy.push(slot);
        }

        // rv0p = P([72+151]*[151+115+405+138]+151-103-226)
        // rv0p = P([k+c]*y_agg_secret_key+c-a-b)
        // rv0p = P([k+c]*y_agg_secret_key+2*c-ry)
        // ry
        // k=rc[PARTS-1].decrypt(&sum_secret_key)
        // c=rv0_parts[PARTS-1]
        let rvyp = mul_mod(&add_mod(&rc[PARTS-1].decrypt(&sum_secret_key), &rv0_parts[PARTS-1], &curve.q).unwrap(), &y_agg_secret_key, &curve.q).unwrap();
        let rvyp = sub_mod(&add_mod(&rvyp, &x2_mod(&rv0_parts[PARTS-1], &curve.q).unwrap(), &curve.q).unwrap(), &ry, &curve.q);

        (
            rvy,
            rv0, // TODO: поменять output параметры местами, чтобы не делать clone()
            make_verifying_key(&curve, &rvyp).unwrap(),
            // (vec![295,148,360]).iter().map(|v| BigInt::from(v.clone())).collect::<Vec<_>>()
            c_points
        )
    };

    // Вспомогательная функция создаёт параметры для i-того участника (банка) на основе параметров владельца всей суммы (налоговой) и контролёра (аудитора)
    let mut create_parts = |value: u64, id: usize, count: usize, rcid: &U512, rv0id: &U512, public_keys: &[&Point; 4]| -> (Point, Vec<Slot>, Vec<Point>) {
        let x: u64 = value; // Суммы дохода пользователя U в банке 1 за определённый год Y

        /////////////////////////////////////////////////////////
        // rx вычисляется из доказательства диапазона range_prove
        let (c_keys, c_points, confidential_value) = range_prove(&curve, x as u128, RANGE, &x_agg_secret_keys[id]).unwrap();
        // println!("Confidential Point {id}:\n{:x?}", &confidential_value);
        // TODO: валидировать c_points относительно ry_confidential_value: range_verify()
        // Сокрытие value от брутфорса ключём k и ключами rri из доказательства RANGE
        // 340 = (rr0 + rr1<<1 + rr2<<2+...+rr127<<127)*k
        // P(340+49) = P(k*(rr0 + rr1<<1 + rr2<<2+...+rr127<<127)+value)
        let rx = mul_mod(&rr_i(&c_keys, &curve.q), &x_agg_secret_keys[id], &curve.q).unwrap(); // 340
        assert!(range_verify(&curve, &c_points, RANGE, make_verifying_key(&curve, &add_mod(&rx, &U512::from_u64(x.clone()), &curve.q).unwrap()).unwrap()));
        /////////////////////////////////////////////////////////

        // let rx = create_random(); // rx1: 340
        // let rx1 = BigInt::from(340);

        // let rv_parts = create_random_additive_parts(&(curve.u512_sum([*rcid, *rv0id, rx, U512::from_u64(x.clone())].to_vec())), count).unwrap(); // rv1: 140+103+340+49=632=[159,168,305].sum()
        let rv_parts = create_random_additive_parts(&(curve.u512_sum([
            mul_mod(&add_mod(rcid, rv0id, &curve.q).unwrap(), &x_agg_secret_keys[id], &curve.q).unwrap(),
            add_mod(&rx, &U512::from_u64(x), &curve.q).unwrap()
        ].to_vec())), count).unwrap(); // X1: [[140 + 103]*[345 + 122 + 233 + 244]] + [340 + 49]

        let mut rv = vec![];
        let mut j = 0;
        for (i, v) in rv_parts.iter().enumerate() {
            if i == id { j = 1; } // id - банк №; игнорировать диагональный элемент матрицы, и перейти к следующему публичному ключу
            let slot = Slot::encrypt(v, &public_keys[i+j]);
            smpc_field.set_client_slot(public_keys[id].clone(), i+j, slot.clone());
            rv.push(slot);
        }
        // let rv1 = (vec![159,168,305]).iter().map(|v| BigInt::from(v.clone())).collect::<Vec<_>>();
        // Создание миксованого ключа с участием банка 1
        // let mvx = make_verifying_key(&curve, &(curve.u512_sum([rx, x2_mod(rv0id, &curve.p).unwrap(), *rcid, x2_mod(&U512::from_u64(x), &curve.p).unwrap()].to_vec()))).unwrap(); // mvx1: 340+2*103+140+2*49=784

        // X1: P([140+103]*[345+122+233+244]+2*103+49) + [P(340+49) восстанавливается из c_points для подтверждения RANGE]
        // X2: P([ 30+226]*[108+263+310+159]+2*226+51) + [P(158+51) восстанавливается из c_points для подтверждения RANGE]

        // x_agg_secret_keys[id]
        let mvx_left = mul_mod(&add_mod(rcid, rv0id, &curve.q).unwrap(), &x_agg_secret_keys[id], &curve.q).unwrap();
        let mvx_right = add_mod(&x2_mod(rv0id, &curve.q).unwrap(), &U512::from_u64(x.clone()), &curve.q).unwrap();
        let mvx = make_verifying_key(&curve, &add_mod(&mvx_left, &mvx_right, &curve.q).unwrap()).unwrap();

        (
            mvx, // P([140+103]*[345+122+233+244]+2*103+49)
            rv,
            c_points // вычисляется из P(340+49)
        )
    };

    // Банк 1
    // Каждая часть rv1[i] шифруется ключём соответствующего участника-приёмщика значения
    let (mvx1, rv1, c_points1) = create_parts(45, 0, PARTS, &rc[0].decrypt(&part1_secret_key), &rv0[0].decrypt(&part1_secret_key), &public_keys);

    // Банк 2
    // Каждая часть rv2[i] шифруется ключём соответствующего участника-приёмщика значения
    let (mvx2, rv2, c_points2) = create_parts(55, 1, PARTS, &rc[1].decrypt(&part2_secret_key), &rv0[1].decrypt(&part2_secret_key), &public_keys);

    // Банк 3
    // Каждая часть rv2[i] шифруется ключём соответствующего участника-приёмщика значения
    // let (mvx3, rv3) = create_parts(50, 2, PARTS, &rc[2].decrypt(&part3_secret_key), &rv0[2].decrypt(&part3_secret_key), &public_keys);

    // Контролёр раздаёт банку1 (140), банку2 (30) и налоговой (72) большие случайные числа, предварительно шифруя их соответствующими публичными ключами получателей
    // Налоговая раздаёт банку1 (103), банку2 (226) и контролёру (151) большие случайные числа, предварительно шифруя их соответствующими публичными ключами получателей
    // Налоговая (ry) отправляет банку1 (rv0[0] и rvy[0]), банку2 (rv0[1] и rvy[1]) и контролёру (rv0[2] и rvy[2]) частичные значения, предварительно шифруя их соответствующими ключами получателей
    // Банк1 (rx1) отправляет банку2 (rv1[0]), налоговой (rv1[1]) и контролёру (rv1[2]) частичные значения, предварительно шифруя их соответствующими ключами получателей
    // Банк2 (rx2) отправляет банку1 (rv2[0]), налоговой (rv2[1]) и контролёру (rv2[2]) частичные значения, предварительно шифруя их соответствующими ключами получателей

    // Создание миксованых ключей с участием банков и налоговой (матрица частичных значений)
    let rv = [&rv1, &rv2, &rvy]; // columns: 0 | 1 | 2
    let z = U512::zero();
    let mx1 = make_verifying_key(&curve, &(curve.u512_sum([z, rv[1][0].decrypt(&part1_secret_key), rv[2][0].decrypt(&part1_secret_key)].to_vec()))).unwrap(); // публикует банк1: 474=[0,179,295].sum()
    let mx2 = make_verifying_key(&curve, &(curve.u512_sum([rv[0][0].decrypt(&part2_secret_key), z, rv[2][1].decrypt(&part2_secret_key)].to_vec()))).unwrap(); // публикует банк2: 307=[159,0,148].sum()
    // ..., mx3, mx4, ..., mxn
    let my  = make_verifying_key(&curve, &(curve.u512_sum([rv[0][1].decrypt(&sum_secret_key), rv[1][1].decrypt(&sum_secret_key), z].to_vec())     )).unwrap(); // публикует налоговая: 329=[168,161,0].sum()
    // DEBUG:
    // let mc1 = rv[0][2].decrypt(&ctrl_secret_key);
    // let mc2 = rv[1][2].decrypt(&ctrl_secret_key);
    // let mc3 = rv[2][2].decrypt(&ctrl_secret_key);
    // println!("MC:\n{:#?}\n{:#?}\n{:#?}", &mc1, &mc2, mc3);
    // ======
    // ключ контролёра
    let mc  = make_verifying_key(&curve, &(curve.u512_sum([rv[0][2].decrypt(&ctrl_secret_key), rv[1][2].decrypt(&ctrl_secret_key), rv[2][2].decrypt(&ctrl_secret_key)].to_vec()))).unwrap(); // вычисляет контролёр: 790=[305,125,360].sum()

    // let rv0x2rc = make_verifying_key(&curve, &(2*&rv0[PARTS-1].decrypt(&ctrl_secret_key)+&rc_secret)).unwrap(); // вычисляет контролёр: 374=2*151+72
    // let rv0x2 = make_verifying_key(&curve, &(x2_mod(&rv0[PARTS-1].decrypt(&ctrl_secret_key), &curve.p /* NB! или &curve.q (выяснить) */).unwrap())).unwrap(); // вычисляет налоговая: 302=2*151
    // let prc = make_verifying_key(&curve, &rc_secret).unwrap(); // ключ контролёра (TODO: объединяется в публичный ключ налоговой: rv0x2+prc)
    // rv0p = P([72+151]*[151+115+405+138]+151-103-226)
    // rv0p = P([72+151]*[151+115+405+138]+151-103-226)
    // rv0p = P([k+c]*y_agg_secret_key+c-a-b)
    // ry = 480
    // c=151, a=103, b=226
    // −178=151-103-226=c-a-b=rv0[PARTS-1].decrypt(&ctrl_secret_key)-rv0[0].decrypt(&ctrl_secret_key)-rv0[1].decrypt(&ctrl_secret_key)
    // rv0[PARTS-1].decrypt(&ctrl_secret_key)
    
    let mvx1_vp = range_point_from_bits(&curve, &c_points1, RANGE);
    // println!("mvx1_vp Point:\n{:x?}", &mvx1_vp);
    let mvx2_vp = range_point_from_bits(&curve, &c_points2, RANGE);
    // println!("mvx1_vp Point:\n{:x?}", &mvx2_vp);

    // Отладка
    let mut matrix_points = BTreeMap::new();
    matrix_points.insert(part1_public_key.x.clone(), mx1.clone());
    matrix_points.insert(part2_public_key.x.clone(), mx2.clone());
    matrix_points.insert(sum_public_key.x.clone(), my.clone());
    // println!("Matrix points(from origin):\n{:#?}", &matrix_points);
    // println!("Matrix Controller Point:\n{:#?}", &mc);

    let mut list_points = BTreeMap::new();
    list_points.insert(part1_public_key.x.clone(), mvx1.clone());
    list_points.insert(part2_public_key.x.clone(), mvx2.clone());
    // list_points.insert(sum_public_key.x.clone(), rv0x2.clone());
    list_points.insert(sum_public_key.x.clone(), rvyp.clone());

    // После публикации участниками [mx1, mx2, my, mc] и [mvx1, mvx2, 2*rv0[PARTS-1], rc[PARTS-1]] любой желающий сможет убедиться в корректности баланса
    let p1 = curve.point_sum(vec![mx1, mx2, my, mc]).unwrap(); // вычисляет контролёр: 1900=[474,307,329,790].sum()
    let p2 = curve.point_sum(vec![mvx1, mvx1_vp, mvx2, mvx2_vp, rvyp/*rv0x2, prc*/]).unwrap(); // вычисляет контролёр: 1900=[784,742,302,74].sum()

    // Если контролёр решит опубликовать результат для сверки произвольными участниками,
    // то для этого ему понадобится выполнить публикацию ключей: mc для p1 и rv0x2rc для p2

    // left (p1):
    // X1: P(95234+72745)
    // X2: P(85345+45790)
    //  Y: P(51345+63234)
    //  C: P(93091+56781+62452)
    //   = P(626017) = P(95234+72745) + P(85345+45790) + P(51345+63234) + P(93091+56781+62452)
    // right (p2):
    // X1: P([140+103]*[345+122+233+244]+2*103+49) + [P(340+49) восстанавливается из c_points для подтверждения RANGE]
    // X2: P([ 30+226]*[108+263+310+159]+2*226+51) + [P(158+51) восстанавливается из c_points для подтверждения RANGE]
    //  Y: P([72+151]*[151+115+405+138]+151-103-226)
    //   = P(626017) = P([140+103]*[345+122+233+244]+2*103+49) + P(340+49) + P([ 30+226]*[108+263+310+159]+2*226+51) + P(158+51) + P([72+151]*[151+115+405+138]+151-103-226)

    assert_eq!(&p1, &p2); // 1900==1900
    // println!("Assert Points:\n{:x?}\n{:x?}", &p1, &p2); // здесь новая версия валидируется (с доказательством RANGE)

    // Отладка методов используемых при сетевом взаимодействии
    smpc_field.set_matrix_points_debug(matrix_points);
    smpc_field.set_list_points_debug(list_points);

    let result = smpc_field.get_solution(&ctrl_secret_key); // TODO: добавить обновление в структуры для сетевого кода
    // println!("Solution: {:x?}", &result);
}