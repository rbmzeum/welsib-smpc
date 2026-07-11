use std::fs::File;
use std::io::{self, BufRead};
use welsib_u512::u512::U512;
use welsib_u512_ec::point::Point;

struct ParsedData {
    public_keys: Vec<Point>,
    matrix_points: Vec<Point>,
    list_points: Vec<Point>,
    bit_proof_points: Vec<Point>,
    controller_matrix_point: Option<Point>,
    p1: Option<Point>,
    p2: Option<Point>,
}

fn parse_u512_from_str(s: &str) -> Option<U512> {
    // Ищем паттерн U512([число, число, ...])
    let start = s.find("U512([")?;
    let end = s.find("])")?;
    let inner = &s[start + 6..end];
    
    let numbers: Vec<u64> = inner
        .split(',')
        .map(|s| s.trim().parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    
    if numbers.len() == 8 {
        Some(U512::new([
            numbers[0], numbers[1], numbers[2], numbers[3],
            numbers[4], numbers[5], numbers[6], numbers[7]
        ]))
    } else {
        None
    }
}

fn parse_point_from_str(s: &str) -> Option<Point> {
    // Ищем паттерн Point { x: U512([...]), y: U512([...]) }
    if let Some(x_start) = s.find("x: U512([") {
        let x_end = s.find("]), y:")?;
        let y_start = s.find("y: U512([")?;
        let y_end = s.find("]) }")?;
        
        let x_str = &s[x_start + 9..x_end];
        let y_str = &s[y_start + 9..y_end];
        
        let x_numbers: Vec<u64> = x_str
            .split(',')
            .map(|s| s.trim().parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()?;
        
        let y_numbers: Vec<u64> = y_str
            .split(',')
            .map(|s| s.trim().parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()?;
        
        if x_numbers.len() == 8 && y_numbers.len() == 8 {
            Some(Point {
                x: U512::new([
                    x_numbers[0], x_numbers[1], x_numbers[2], x_numbers[3],
                    x_numbers[4], x_numbers[5], x_numbers[6], x_numbers[7]
                ]),
                y: U512::new([
                    y_numbers[0], y_numbers[1], y_numbers[2], y_numbers[3],
                    y_numbers[4], y_numbers[5], y_numbers[6], y_numbers[7]
                ]),
            })
        } else {
            None
        }
    } else {
        // Пытаемся извлечь только x координату
        if let Some(x) = parse_u512_from_str(s) {
            Some(Point { x, y: U512::zero() })
        } else {
            None
        }
    }
}

fn parse_debug_log(path: &str) -> io::Result<ParsedData> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    
    let mut data = ParsedData {
        public_keys: Vec::new(),
        matrix_points: Vec::new(),
        list_points: Vec::new(),
        bit_proof_points: Vec::new(),
        controller_matrix_point: None,
        p1: None,
        p2: None,
    };
    
    for line_result in reader.lines() {
        let line = line_result?;
        
        // 1. Парсинг публичных ключей из строк типа:
        // "DEBUG solution: Получена point_list от клиента U512([...]): U512([...])"
        if line.contains("Получена point_list от клиента") || 
           line.contains("Получена point_matrix от клиента") ||
           line.contains("Получен bit_proof") && line.contains("от клиента") {
            
            if let Some(client_start) = line.find("от клиента U512") {
                let client_part = &line[client_start + 12..];
                if let Some(public_key) = parse_u512_from_str(client_part) {
                    let point = Point { x: public_key, y: U512::zero() };
                    if !data.public_keys.iter().any(|p| p.x == point.x) {
                        data.public_keys.push(point);
                    }
                }
            }
        }
        
        // 2. Парсинг matrix точек
        if line.contains("Получена point_matrix от клиента") && line.contains(": U512") {
            if let Some(colon_idx) = line.rfind(": U512") {
                let point_str = &line[colon_idx..];
                if let Some(point) = parse_point_from_str(point_str) {
                    data.matrix_points.push(point);
                }
            }
        }
        
        // 3. Парсинг list точек
        if line.contains("Получена point_list от клиента") && line.contains(": U512") {
            if let Some(colon_idx) = line.rfind(": U512") {
                let point_str = &line[colon_idx..];
                if let Some(point) = parse_point_from_str(point_str) {
                    data.list_points.push(point);
                }
            }
        }
        
        // 4. Парсинг точек из bit_proofs
        if line.contains("Точка из bit_proofs для клиента") && line.contains("= U512") {
            if let Some(equal_idx) = line.find("= U512") {
                let point_str = &line[equal_idx + 2..];
                if let Some(point) = parse_point_from_str(point_str) {
                    data.bit_proof_points.push(point);
                }
            }
        }
        
        // 5. Парсинг controller matrix point
        if line.contains("matrix_controller_point = U512") {
            if let Some(equal_idx) = line.find("= U512") {
                let point_str = &line[equal_idx + 2..];
                if let Some(point) = parse_point_from_str(point_str) {
                    data.controller_matrix_point = Some(point);
                }
            }
        }
        
        // 6. Парсинг p1 и p2
        if line.contains("p1 = U512") {
            if let Some(equal_idx) = line.find("= U512") {
                let point_str = &line[equal_idx + 2..];
                if let Some(point) = parse_point_from_str(point_str) {
                    data.p1 = Some(point);
                }
            }
        }
        
        if line.contains("p2 = U512") {
            if let Some(equal_idx) = line.find("= U512") {
                let point_str = &line[equal_idx + 2..];
                if let Some(point) = parse_point_from_str(point_str) {
                    data.p2 = Some(point);
                }
            }
        }
    }
    
    Ok(data)
}

// Функция для сопоставления с переменными несетевой версии
fn map_to_non_network_variables(data: &ParsedData) {
    println!("=== Сопоставление с несетевой версией ===");
    
    // Публичные ключи (part1_public_key, part2_public_key, sum_public_key)
    if data.public_keys.len() >= 3 {
        println!("part1_public_key.x = {:?}", data.public_keys[0].x);
        println!("part2_public_key.x = {:?}", data.public_keys[1].x);
        println!("sum_public_key.x = {:?}", data.public_keys[2].x);
    }
    
    // Matrix точки (mx1, mx2, my)
    if data.matrix_points.len() >= 3 {
        println!("mx1.x = {:?}", data.matrix_points[0].x);
        println!("mx2.x = {:?}", data.matrix_points[1].x);
        println!("my.x = {:?}", data.matrix_points[2].x);
    }
    
    // List точки (mvx1, mvx2, rvyp)
    if data.list_points.len() >= 3 {
        println!("mvx1.x = {:?}", data.list_points[0].x);
        println!("mvx2.x = {:?}", data.list_points[1].x);
        println!("rvyp.x = {:?}", data.list_points[2].x);
    }
    
    // Точки из BitProve (mvx1_vp, mvx2_vp)
    if data.bit_proof_points.len() >= 2 {
        println!("mvx1_vp.x = {:?}", data.bit_proof_points[0].x);
        println!("mvx2_vp.x = {:?}", data.bit_proof_points[1].x);
    }
    
    // Matrix точка контролёра (mc)
    if let Some(mc) = &data.controller_matrix_point {
        println!("mc.x = {:?}", mc.x);
    }
    
    // Финальные точки p1 и p2
    if let Some(p1) = &data.p1 {
        println!("p1.x = {:?}", p1.x);
    }
    if let Some(p2) = &data.p2 {
        println!("p2.x = {:?}", p2.x);
    }
}

fn main() -> io::Result<()> {
    let path = "/home/vs/Projects/welsib-independent/welsib-smpc/example/debug_server.txt";
    let parsed_data = parse_debug_log(path)?;

    // Выводим результаты парсинга
    println!("Найдено публичных ключей: {}", parsed_data.public_keys.len());
    println!("Найдено matrix точек: {}", parsed_data.matrix_points.len());
    println!("Найдено list точек: {}", parsed_data.list_points.len());
    println!("Найдено bit_proof точек: {}", parsed_data.bit_proof_points.len());

    // Сопоставляем с несетевой версией
    map_to_non_network_variables(&parsed_data);

    Ok(())
}