use welsib_u512::u512::{U512, U1024, U512Sub, U512Shr};
use welsib_random::strong_random as random;

fn get_u512_random_range(range: &U512) -> U512 {
    // TODO: if range == U512::zero() { return None or panic! }
    if range.get()[7] == 0 {
        // TODO: оптимизировать (без использования остатка от деления на цело
        (U1024::new([
            random::<u64>(), random::<u64>(), random::<u64>(), random::<u64>(),
            random::<u64>(), random::<u64>(), random::<u64>(), random::<u64>(),
            0, 0, 0, 0, 0, 0, 0, 0
        ]) % range).unwrap()
    } else { 
        U512::new([
            random::<u64>(), random::<u64>(), random::<u64>(), random::<u64>(),
            random::<u64>(), random::<u64>(), random::<u64>(), random::<u64>() % range.get()[7]
        ])
    }
}

/**
 * Вспомогательная функция разделяющая секретное большое случайное число на случайные части сумма которых равна исходному secret_value числу
 */
pub fn create_random_additive_parts(value: &U512, count: usize) -> Option<Vec<U512>> {
    // Проверка некорректных входных данных
    if count == 0 {
        return None;
    }

    // Обработка случая с одним элементом
    if count == 1 {
        return Some(vec![value.clone()]);
    }

    // Все элементы будут нулями
    if *value == U512::zero() {
        return Some(vec![U512::zero(); count]);
    }

    let mut dividers = Vec::with_capacity(count - 1);

    // Генерируем случайные разделители
    for _ in 0..(count - 1) {
        let num = get_u512_random_range(value);
        dividers.push(num);
    }

    // Сортируем разделители и строим точки разбиения
    dividers.sort();
    let mut points = vec![U512::zero()];
    points.extend(dividers);
    points.push(value.clone());

    // Вычисляем разницы между соседними точками
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        result.push(points[i + 1].clone() - &points[i].clone());
    }

    Some(result)
}
