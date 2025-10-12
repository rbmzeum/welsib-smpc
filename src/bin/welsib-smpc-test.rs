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
        key.shr(4);
        key
    };

    // N == A+B+C+D || S(N) == S(A)+S(B)+S(C)+S(B)
    // Доказательство верности равенства y == x1 + x2 + ... + xn без разглашения y, x1, x2, ..., xn (не 100%, зависит от криптостойкости параметров эллиптической кривой)

    // Банки и налоговая, каждый на своей стороне, генерируют случайные большие числа (секреты), от 0 до curve.q - u64::MAX_VALUE * n(банков)
    // ((((10000*10000*512*5)/8)/1024)/1024)/1024= порядка 30 гигабайт в оперативной памяти будет занимать матрица при PARTS = 10000 (участников)
    const PARTS: usize = 3; // 1 - банк1, 2 - банк2, 3 - налоговая (4 - проверяющий, отдельно)

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

    // TODO: подготовка ключей для цифровых подписей

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
    let (rvy, rv0) = {
        let y: u64 = 100; // Сумма задекларированная пользователем U в налоговую с которой уплачивается налог за определённый год Y
        let ry = create_random(); // ry: 480
        // let ry = BigInt::from(480);
        let rv0_parts = create_random_additive_parts(&ry, PARTS).unwrap(); // rv0: 480=[103,226,151].sum()
        let mut rv0 = vec![];
        let mut j = 0;
        for (i, value) in rv0_parts.iter().enumerate() {
            if i == PARTS-1 { j = 1; } // игнорировать диагональный элемент матрицы, и перейти к следующему публичному ключу
            let slot = Slot::encrypt(value, &public_keys[i+j]);
            smpc_field.set_main_client_slot(public_keys[i+j].clone(), slot.clone());
            rv0.push(slot);
        }
        let rvy_parts = create_random_additive_parts(&(curve.u512_sum([rc[PARTS-1].decrypt(&sum_secret_key), rv0_parts[PARTS-1], ry, U512::from_u64(y)].to_vec())), PARTS).unwrap(); // rvy: 72+151+480+100=803=[295,148,360].sum()
        let mut rvy = vec![];
        let mut j = 0;
        for (i, value) in rvy_parts.iter().enumerate() {
            if i == PARTS-1 { j = 1; } // игнорировать диагональный элемент матрицы, и перейти к следующему публичному ключу
            let slot = Slot::encrypt(value, &public_keys[i+j]);
            smpc_field.set_client_slot(sum_public_key.clone(), i+j, slot.clone());
            rvy.push(slot);
        }
        (
            rvy,
            rv0, // TODO: поменять output параметры местами, чтобы не делать clone()
            // (vec![295,148,360]).iter().map(|v| BigInt::from(v.clone())).collect::<Vec<_>>()
        )
    };

    // Вспомогательная функция создаёт параметры для i-того участника (банка) на основе параметров владельца всей суммы (налоговой) и контролёра (аудитора)
    let mut create_parts = |value: u64, id: usize, count: usize, rcid: &U512, rv0id: &U512, public_keys: &[&Point; 4]| -> (Point, Vec<Slot>) {
        let x: u64 = value; // Суммы дохода пользователя U в банке 1 за определённый год Y
        let rx = create_random(); // rx1: 340
        // let rx1 = BigInt::from(340);
        let rv_parts = create_random_additive_parts(&(curve.u512_sum([*rcid, *rv0id, rx, U512::from_u64(x)].to_vec())), count).unwrap(); // rv1: 140+103+340+49=632=[159,168,305].sum()
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
        let mvx = make_verifying_key(&curve, &(curve.u512_sum([rx, x2_mod(rv0id, &curve.p).unwrap(), *rcid, x2_mod(&U512::from_u64(x), &curve.p).unwrap()].to_vec()))).unwrap(); // mvx1: 340+2*103+140+2*49=784
        (
            mvx,
            rv,
        )
    };

    // Банк 1
    // Каждая часть rv1[i] шифруется ключём соответствующего участника-приёмщика значения
    let (mvx1, rv1) = create_parts(45, 0, PARTS, &rc[0].decrypt(&part1_secret_key), &rv0[0].decrypt(&part1_secret_key), &public_keys);

    // Банк 2
    // Каждая часть rv2[i] шифруется ключём соответствующего участника-приёмщика значения
    let (mvx2, rv2) = create_parts(55, 1, PARTS, &rc[1].decrypt(&part2_secret_key), &rv0[1].decrypt(&part2_secret_key), &public_keys);

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
    let mc  = make_verifying_key(&curve, &(curve.u512_sum([rv[0][2].decrypt(&ctrl_secret_key), rv[1][2].decrypt(&ctrl_secret_key), rv[2][2].decrypt(&ctrl_secret_key)].to_vec()))).unwrap(); // вычисляет контролёр: 790=[305,125,360].sum()

    // let rv0x2rc = make_verifying_key(&curve, &(2*&rv0[PARTS-1].decrypt(&ctrl_secret_key)+&rc_secret)).unwrap(); // вычисляет контролёр: 374=2*151+72
    let rv0x2 = make_verifying_key(&curve, &(x2_mod(&rv0[PARTS-1].decrypt(&ctrl_secret_key), &curve.p /* NB! или &curve.q (выяснить) */).unwrap())).unwrap(); // вычисляет налоговая: 302=2*151
    let prc = make_verifying_key(&curve, &rc_secret).unwrap(); // ключ контролёра

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
    list_points.insert(sum_public_key.x.clone(), rv0x2.clone());

    // После публикации участниками [mx1, mx2, my, mc] и [mvx1, mvx2, 2*rv0[PARTS-1], rc[PARTS-1]] любой желающий сможет убедиться в корректности баланса
    let p1 = curve.point_sum(vec![mx1, mx2, my, mc]).unwrap(); // вычисляет контролёр: 1900=[474,307,329,790].sum()
    let p2 = curve.point_sum(vec![mvx1, mvx2, rv0x2, prc]).unwrap(); // вычисляет контролёр: 1900=[784,742,302,74].sum()

    // Если контролёр решит опубликовать результат для сверки произвольными участниками,
    // то для этого ему понадобится выполнить публикацию ключей: mc для p1 и rv0x2rc для p2

    assert_eq!(&p1, &p2); // 1900==1900
    // println!("Assert Points:\n{:#?}\n{:#?}", &p1, &p2);

    // Отладка методов используемых при сетевом взаимодействии
    smpc_field.set_matrix_points_debug(matrix_points);
    smpc_field.set_list_points_debug(list_points);

    let result = smpc_field.get_solution(&ctrl_secret_key);
    // println!("Solution: {:#?}", &result);
}