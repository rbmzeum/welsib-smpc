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

/// Демонстрационный пример конфиденциальных многосторонних вычислений (Secure Multi-Party Computation)
/// 
/// # Основная концепция
/// Доказывает корректность равенства Y = X₁ + X₂ + ... + Xₙ без раскрытия значений Y, X₁, X₂, ..., Xₙ
/// 
/// # Сценарии применения
/// 
/// ## Корпоративный аудит
/// ```text
/// Компания: Y = 1,000,000 (общий бюджет)
/// Подразделения: X₁ = 300,000, X₂ = 400,000, X₃ = 300,000
/// Аудитор проверяет: 300,000 + 400,000 + 300,000 = 1,000,000
/// без раскрытия бюджетов подразделений
/// ```
/// 
/// ## Медицинская статистика
/// ```text
/// Больницы предоставляют агрегированные данные о заболеваемости
/// Исследовательский центр получает: Y = общее количество случаев
/// без доступа к персональным данным пациентов из каждой больницы
/// ```
/// 
/// ## Цепочки поставок
/// ```text
/// Поставщики: X₁, X₂, X₃ - объемы поставок
/// Логистическая компания: Y = общий объем
/// Проверка без раскрытия коммерческой информации каждого поставщика
/// ```
/// 
/// ## Кросс-банковские операции
/// ```text
/// Банки: X₁, X₂ - суммы на счетах клиента
/// Центральный банк: Y = общая сумма
/// Проверка соответствия при межбанковских переводах
/// ```
fn main() {
    let curve = EllipticCurve::make_curve_welsib();
    let mut smpc_field = SMPCField::new();

    /// Генерация случайных ключей с ограничением диапазона для безопасности
    let create_random = || {
        let mut key = make_signing_key(&curve);
        // Ограничение диапазона для предотвращения переполнения
        // key.shr(4);
        key
    };

    // =========================================================================
    // КОНФИГУРАЦИЯ СИСТЕМЫ
    // =========================================================================

    /// Количество участников протокола
    /// - PARTS-1: участники с частичными суммами (банки)
    /// - Последний участник: владелец общей суммы (налоговая)
    const PARTS: usize = 3;
    
    /// Размер битового диапазона для доказательства диапазона
    /// Ограничивает максимальное значение конфиденциальных данных
    const RANGE: usize = 128;

    // Генерация ключевых пар для всех участников
    let (ctrl_secret_key, ctrl_public_key) = make_keypair(&curve); // Контролёр/Аудитор
    let (sum_secret_key, sum_public_key) = make_keypair(&curve);    // Налоговая (владелец Y)
    let (part1_secret_key, part1_public_key) = make_keypair(&curve); // Банк 1 (владелец X₁)
    let (part2_secret_key, part2_public_key) = make_keypair(&curve); // Банк 2 (владелец X₂)

    // Публичные ключи всех участников для шифрования сообщений
    let public_keys = [
        &part1_public_key, // Индекс 0: Банк 1
        &part2_public_key, // Индекс 1: Банк 2  
        &sum_public_key,   // Индекс 2: Налоговая
        &ctrl_public_key,  // Индекс 3: Контролёр
    ];

    // =========================================================================
    // ПРОТОКОЛ ОБМЕНА ЧАСТИЧНЫМИ КЛЮЧАМИ
    // =========================================================================

    /// Матрица дополнительных ключей для усиления конфиденциальности
    /// 
    /// Структура матрицы 4×3:
    /// ```text
    ///         X₁     X₂      Y      C
    /// X₁: [  345,   108,   151  ] = 604
    /// X₂: [  122,   263,   115  ] = 500  
    /// Y:  [  233,   310,   405  ] = 948
    /// C:  [  244,   159,   138  ] = 541
    /// ```
    /// Каждый участник получает свою строку матрицы
    let kx1_secret = create_random();
    let kx2_secret = create_random();
    let ky_secret = create_random();
    let kc_secret = create_random();

    let kx1_parts = create_random_additive_parts(&kx1_secret, PARTS).unwrap();
    let kx2_parts = create_random_additive_parts(&kx2_secret, PARTS).unwrap();
    let ky_parts = create_random_additive_parts(&ky_secret, PARTS).unwrap();
    let kc_parts = create_random_additive_parts(&kc_secret, PARTS).unwrap();

    let matrix_keys = vec![
        kx1_parts, // Строка для X₁: [345, 108, 151]
        kx2_parts, // Строка для X₂: [122, 263, 115]
        ky_parts,  // Строка для Y:  [233, 310, 405]
        kc_parts   // Строка для C:  [244, 159, 138]
    ];

    // =========================================================================
    // СЕТЕВОЙ ОБМЕН КЛЮЧАМИ (ЭМУЛЯЦИЯ)
    // =========================================================================

    /// Каждый участник шифрует свою строку матрицы ключей
    /// и отправляет каждому другому участнику соответствующую часть
    let mut kx1_slots = vec![];
    let mut kx2_slots = vec![];
    let mut ky_slots = vec![];
    let mut kc_slots = vec![];

    // Клиент 1 (X₁) шифрует свою строку ключей
    let id = 0;
    for i in 0..PARTS {
        let slot = Slot::encrypt(&matrix_keys[id][i], &public_keys[i]);
        kx1_slots.push(slot);
    }

    // Клиент 2 (X₂) шифрует свою строку ключей  
    let id = 1;
    for i in 0..PARTS {
        let slot = Slot::encrypt(&matrix_keys[id][i], &public_keys[i]);
        kx2_slots.push(slot);
    }

    // Клиент 3 (Y) шифрует свою строку ключей
    let id = 2;
    for i in 0..PARTS {
        let slot = Slot::encrypt(&matrix_keys[id][i], &public_keys[i]);
        ky_slots.push(slot);
    }

    // Клиент 4 (C) шифрует свою строку ключей
    let id = 3;
    for i in 0..PARTS {
        let slot = Slot::encrypt(&matrix_keys[id][i], &public_keys[i]);
        kc_slots.push(slot);
    }

    // =========================================================================
    // АГРЕГАЦИЯ КЛЮЧЕЙ УЧАСТНИКАМИ
    // =========================================================================

    /// Каждый участник вычисляет свой агрегированный секретный ключ
    /// как сумму полученных частей от всех участников
    let id = 0; // Клиент X₁
    let x1_agg_secret_key = curve.u512_sum(vec![
        kx1_slots[id].decrypt(&part1_secret_key),
        kx2_slots[id].decrypt(&part1_secret_key), 
        ky_slots[id].decrypt(&part1_secret_key),
        kc_slots[id].decrypt(&part1_secret_key)
    ]);

    let id = 1; // Клиент X₂
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

    // =========================================================================
    // ПРОТОКОЛ КОНТРОЛЁРА (АУДИТОРА)
    // =========================================================================

    /// Контролёр генерирует случайное число и разделяет его на части
    /// Каждая часть шифруется для соответствующего участника
    /// 
    /// Пример: rc = 242 = [140, 30, 72]
    let (rc, rc_secret) = {
        let rc = create_random();
        smpc_field.set_random_control_sum_debug(rc.clone());
        
        let parts = create_random_additive_parts(&rc, PARTS).unwrap();
        smpc_field.set_random_control_values_debug(parts.clone());
        
        let mut output = vec![];
        for (i, value) in parts.iter().enumerate() {
            let slot = Slot::encrypt(value, &public_keys[i]);
            smpc_field.set_random_control_slot(public_keys[i].clone(), slot.clone());
            output.push(slot);
        }
        (output, parts[PARTS-1].clone())
    };

    // =========================================================================
    // ПРОТОКОЛ НАЛОГОВОЙ (ВЛАДЕЛЕЦ ОБЩЕЙ СУММЫ Y)
    // =========================================================================

    /// Налоговая создаёт конфиденциальное представление общей суммы Y
    /// с использованием доказательства диапазона
    /// 
    /// Пример: Y = 100
    let (rvy, rv0, rvyp, rvy_c_points) = {
        let y: u64 = 100;

        // Создание доказательства диапазона для значения Y
        let (c_keys, c_points, confidential_value) = range_prove(&curve, y as u128, RANGE, &y_agg_secret_key).unwrap();
        
        // Вычисление ry через доказательство диапазона
        let ry = mul_mod(&rr_i(&c_keys, &curve.q), &y_agg_secret_key, &curve.q).unwrap();
        
        // Верификация доказательства диапазона
        assert!(range_verify(&curve, &c_points, RANGE, 
            make_verifying_key(&curve, &add_mod(&ry, &U512::from_u64(y.clone()), &curve.q).unwrap()).unwrap()));

        // Разделение ry на части для участников
        let rv0_parts = create_random_additive_parts(&ry, PARTS).unwrap();
        let mut rv0 = vec![];
        let mut j = 0;
        for (i, value) in rv0_parts.iter().enumerate() {
            if i == PARTS-1 { j = 1; }
            let slot = Slot::encrypt(value, &public_keys[i+j]);
            smpc_field.set_main_client_slot(public_keys[i+j].clone(), slot.clone());
            rv0.push(slot);
        }

        // Создание конфиденциального представления Y
        let rvy_parts = create_random_additive_parts(&(curve.u512_sum([
            mul_mod(&add_mod(&rc[PARTS-1].decrypt(&sum_secret_key), &rv0_parts[PARTS-1], &curve.q).unwrap(), 
                     &y_agg_secret_key, &curve.q).unwrap(),
            add_mod(&ry, &U512::from_u64(y), &curve.q).unwrap()
        ].to_vec())), PARTS).unwrap();

        let mut rvy = vec![];
        let mut j = 0;
        for (i, value) in rvy_parts.iter().enumerate() {
            if i == PARTS-1 { j = 1; }
            let slot = Slot::encrypt(value, &public_keys[i+j]);
            smpc_field.set_client_slot(sum_public_key.clone(), i+j, slot.clone());
            rvy.push(slot);
        }

        // Создание верификационного ключа для Y
        let rvyp = mul_mod(&add_mod(&rc[PARTS-1].decrypt(&sum_secret_key), &rv0_parts[PARTS-1], &curve.q).unwrap(), 
                          &y_agg_secret_key, &curve.q).unwrap();
        let rvyp = sub_mod(&add_mod(&rvyp, &x2_mod(&rv0_parts[PARTS-1], &curve.q).unwrap(), &curve.q).unwrap(), 
                          &ry, &curve.q);

        (rvy, rv0, make_verifying_key(&curve, &rvyp).unwrap(), c_points)
    };

    // =========================================================================
    // ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ УЧАСТНИКОВ С ЧАСТИЧНЫМИ СУММАМИ
    // =========================================================================

    /// Создаёт параметры для участника с частичной суммой Xᵢ
    /// 
    /// # Параметры
    /// - `value`: фактическое значение Xᵢ
    /// - `id`: идентификатор участника  
    /// - `count`: количество участников
    /// - `rcid`: часть случайного числа от контролёра
    /// - `rv0id`: часть случайного числа от налоговой
    /// 
    /// # Пример для банка 1
    /// ```text
    /// value = 45, id = 0
    /// rcid = 140 (от контролёра)
    /// rv0id = 103 (от налоговой)
    /// Результат: конфиденциальное представление X₁
    /// ```
    let mut create_parts = |value: u64, id: usize, count: usize, rcid: &U512, rv0id: &U512, public_keys: &[&Point; 4]| -> (Point, Vec<Slot>, Vec<Point>) {
        let x: u64 = value;

        // Создание доказательства диапазона для Xᵢ
        let (c_keys, c_points, confidential_value) = range_prove(&curve, x as u128, RANGE, &x_agg_secret_keys[id]).unwrap();
        
        let rx = mul_mod(&rr_i(&c_keys, &curve.q), &x_agg_secret_keys[id], &curve.q).unwrap();
        
        // Верификация доказательства диапазона
        assert!(range_verify(&curve, &c_points, RANGE, 
            make_verifying_key(&curve, &add_mod(&rx, &U512::from_u64(x.clone()), &curve.q).unwrap()).unwrap()));

        // Создание конфиденциального представления Xᵢ
        let rv_parts = create_random_additive_parts(&(curve.u512_sum([
            mul_mod(&add_mod(rcid, rv0id, &curve.q).unwrap(), &x_agg_secret_keys[id], &curve.q).unwrap(),
            add_mod(&rx, &U512::from_u64(x), &curve.q).unwrap()
        ].to_vec())), count).unwrap();

        let mut rv = vec![];
        let mut j = 0;
        for (i, v) in rv_parts.iter().enumerate() {
            if i == id { j = 1; }
            let slot = Slot::encrypt(v, &public_keys[i+j]);
            smpc_field.set_client_slot(public_keys[id].clone(), i+j, slot.clone());
            rv.push(slot);
        }

        // Создание верификационного ключа для Xᵢ
        let mvx_left = mul_mod(&add_mod(rcid, rv0id, &curve.q).unwrap(), &x_agg_secret_keys[id], &curve.q).unwrap();
        let mvx_right = add_mod(&x2_mod(rv0id, &curve.q).unwrap(), &U512::from_u64(x.clone()), &curve.q).unwrap();
        let mvx = make_verifying_key(&curve, &add_mod(&mvx_left, &mvx_right, &curve.q).unwrap()).unwrap();

        (mvx, rv, c_points)
    };

    // =========================================================================
    // СОЗДАНИЕ КОНФИДЕНЦИАЛЬНЫХ ПРЕДСТАВЛЕНИЙ ДЛЯ БАНКОВ
    // =========================================================================

    /// Банк 1 создаёт конфиденциальное представление X₁ = 45
    let (mvx1, rv1, c_points1) = create_parts(45, 0, PARTS, 
        &rc[0].decrypt(&part1_secret_key), 
        &rv0[0].decrypt(&part1_secret_key), 
        &public_keys);

    /// Банк 2 создаёт конфиденциальное представление X₂ = 55  
    let (mvx2, rv2, c_points2) = create_parts(55, 1, PARTS,
        &rc[1].decrypt(&part2_secret_key),
        &rv0[1].decrypt(&part2_secret_key),
        &public_keys);

    // =========================================================================
    // ФОРМИРОВАНИЕ МАТРИЦЫ ВЕРИФИКАЦИОННЫХ КЛЮЧЕЙ
    // =========================================================================

    /// Каждый участник публикует свой верификационный ключ
    /// на основе полученных конфиденциальных частей
    let rv = [&rv1, &rv2, &rvy];
    let z = U512::zero();
    
    // Банк 1 публикует свой ключ
    let mx1 = make_verifying_key(&curve, &(curve.u512_sum([
        z, 
        rv[1][0].decrypt(&part1_secret_key), 
        rv[2][0].decrypt(&part1_secret_key)
    ].to_vec()))).unwrap();

    // Банк 2 публикует свой ключ  
    let mx2 = make_verifying_key(&curve, &(curve.u512_sum([
        rv[0][0].decrypt(&part2_secret_key),
        z,
        rv[2][1].decrypt(&part2_secret_key)
    ].to_vec()))).unwrap();

    // Налоговая публикует свой ключ
    let my = make_verifying_key(&curve, &(curve.u512_sum([
        rv[0][1].decrypt(&sum_secret_key),
        rv[1][1].decrypt(&sum_secret_key), 
        z
    ].to_vec()))).unwrap();

    // Контролёр вычисляет общий ключ
    let mc = make_verifying_key(&curve, &(curve.u512_sum([
        rv[0][2].decrypt(&ctrl_secret_key),
        rv[1][2].decrypt(&ctrl_secret_key),
        rv[2][2].decrypt(&ctrl_secret_key)
    ].to_vec()))).unwrap();

    // =========================================================================
    // ВЕРИФИКАЦИЯ КОРРЕКТНОСТИ ВЫЧИСЛЕНИЙ
    // =========================================================================

    /// Преобразование точек доказательства диапазона в верификационные ключи
    let mvx1_vp = range_point_from_bits(&curve, &c_points1, RANGE);
    let mvx2_vp = range_point_from_bits(&curve, &c_points2, RANGE);

    // Формирование структур данных для верификации
    let mut matrix_points = BTreeMap::new();
    matrix_points.insert(part1_public_key.x.clone(), mx1.clone());
    matrix_points.insert(part2_public_key.x.clone(), mx2.clone());
    matrix_points.insert(sum_public_key.x.clone(), my.clone());

    let mut list_points = BTreeMap::new();
    list_points.insert(part1_public_key.x.clone(), mvx1.clone());
    list_points.insert(part2_public_key.x.clone(), mvx2.clone());
    list_points.insert(sum_public_key.x.clone(), rvyp.clone());

    // =========================================================================
    // ФИНАЛЬНАЯ ПРОВЕРКА КОРРЕКТНОСТИ
    // =========================================================================

    /// Вычисление двух точек для проверки равенства:
    /// - p1: сумма матричных ключей участников
    /// - p2: сумма верификационных ключей с доказательствами диапазона
    /// 
    /// Если p1 == p2, то доказано что:
    /// 1. Y действительно равно сумме X₁ + X₂
    /// 2. Все значения находятся в допустимом диапазоне
    /// 3. Никакие конфиденциальные данные не были раскрыты
    let p1 = curve.point_sum(vec![mx1, mx2, my, mc]).unwrap();
    let p2 = curve.point_sum(vec![mvx1, mvx1_vp, mvx2, mvx2_vp, rvyp]).unwrap();

    // Критическая проверка - если точки равны, доказательство корректно
    assert_eq!(&p1, &p2);

    // =========================================================================
    // ФОРМИРОВАНИЕ РЕЗУЛЬТАТА
    // =========================================================================

    /// Результат может быть сериализован в сертификат
    /// и проверен независимым верификатором
    smpc_field.set_matrix_points_debug(matrix_points);
    smpc_field.set_list_points_debug(list_points);

    let result = smpc_field.get_solution(&ctrl_secret_key);
}