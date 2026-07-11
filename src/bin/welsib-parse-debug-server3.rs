use std::fs::File;
use std::io::{self, BufRead};
use welsib_u512::u512::U512;
use welsib_u512_ec::point::Point;

#[derive(Debug, Default)]
struct ParsedData {
    part1_public_key: Option<Point>,
    part2_public_key: Option<Point>,
    sum_public_key: Option<Point>,
    mx1: Option<Point>,
    mx2: Option<Point>,
    my: Option<Point>,
    mc: Option<Point>,
    mvx1: Option<Point>,
    mvx2: Option<Point>,
    rvyp: Option<Point>,
    mvx1_vp: Option<Point>,
    mvx2_vp: Option<Point>,
    p1: Option<Point>,
    p2: Option<Point>,
}

impl ParsedData {
    fn new() -> Self {
        Self::default()
    }
}

fn parse_u512_from_str(s: &str) -> Option<U512> {
    // Ищем паттерн U512([
    if let Some(start) = s.find("U512([") {
        let sub = &s[start + 6..]; // Пропускаем "U512(["
        if let Some(end) = sub.find("])") {
            let numbers_str = &sub[..end];
            let numbers: Vec<u64> = numbers_str
                .split(',')
                .map(|s| s.trim().parse::<u64>().ok())
                .collect::<Option<Vec<_>>>()?;
            
            if numbers.len() == 8 {
                return Some(U512::new([
                    numbers[0], numbers[1], numbers[2], numbers[3],
                    numbers[4], numbers[5], numbers[6], numbers[7]
                ]));
            }
        }
    }
    None
}

fn parse_debug_log(path: &str) -> io::Result<ParsedData> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    
    let mut data = ParsedData::new();
    let mut client_counter = 0;
    let mut client_map = std::collections::HashMap::new();
    
    for line_result in reader.lines() {
        let line = match line_result {
            Ok(line) => line,
            Err(e) => {
                eprintln!("Ошибка чтения строки: {}", e);
                continue;
            }
        };
        
        // Парсинг point_list
        if line.contains("Получена point_list от клиента") {
            // Ищем начало U512 клиента
            if let Some(client_start) = line.find("от клиента") {
                let after_client = &line[client_start..];
                // Извлекаем U512 клиента
                if let Some(client_x) = parse_u512_from_str(after_client) {
                    let client_id = format!("{:?}", client_x);
                    
                    // Регистрируем нового клиента, если нужно
                    if !client_map.contains_key(&client_id) {
                        client_map.insert(client_id.clone(), client_counter);
                        client_counter += 1;
                        
                        // Сохраняем публичный ключ
                        let point = Point { x: client_x, y: U512::zero() };
                        match client_counter - 1 {
                            0 => data.part1_public_key = Some(point),
                            1 => data.part2_public_key = Some(point),
                            2 => data.sum_public_key = Some(point),
                            _ => {}
                        }
                    }
                    
                    // Извлекаем U512 точки (ищем последний U512 в строке)
                    if let Some(colon_idx) = line.rfind(": U512([") {
                        let point_str = &line[colon_idx..];
                        if let Some(point_x) = parse_u512_from_str(point_str) {
                            let point = Point { x: point_x, y: U512::zero() };
                            if let Some(&client_idx) = client_map.get(&client_id) {
                                match client_idx {
                                    0 => data.mvx1 = Some(point),
                                    1 => data.mvx2 = Some(point),
                                    2 => data.rvyp = Some(point),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Парсинг point_matrix
        if line.contains("Получена point_matrix от клиента") {
            // Ищем начало U512 клиента
            if let Some(client_start) = line.find("от клиента") {
                let after_client = &line[client_start..];
                // Извлекаем U512 клиента
                if let Some(client_x) = parse_u512_from_str(after_client) {
                    let client_id = format!("{:?}", client_x);
                    
                    // Регистрируем нового клиента, если нужно (дублируется с предыдущим)
                    if !client_map.contains_key(&client_id) {
                        client_map.insert(client_id.clone(), client_counter);
                        client_counter += 1;
                        
                        // Сохраняем публичный ключ
                        let point = Point { x: client_x, y: U512::zero() };
                        match client_counter - 1 {
                            0 => data.part1_public_key = Some(point),
                            1 => data.part2_public_key = Some(point),
                            2 => data.sum_public_key = Some(point),
                            _ => {}
                        }
                    }
                    
                    // Извлекаем U512 точки
                    if let Some(colon_idx) = line.rfind(": U512([") {
                        let point_str = &line[colon_idx..];
                        if let Some(point_x) = parse_u512_from_str(point_str) {
                            let point = Point { x: point_x, y: U512::zero() };
                            if let Some(&client_idx) = client_map.get(&client_id) {
                                match client_idx {
                                    0 => data.mx1 = Some(point),
                                    1 => data.mx2 = Some(point),
                                    2 => data.my = Some(point),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Парсинг bit_proof точек
        if line.contains("Точка из bit_proofs для клиента") {
            // Ищем начало U512 клиента
            if let Some(client_start) = line.find("для клиента") {
                let after_client = &line[client_start..];
                // Извлекаем U512 клиента
                if let Some(client_x) = parse_u512_from_str(after_client) {
                    let client_id = format!("{:?}", client_x);
                    
                    // Регистрируем нового клиента, если нужно
                    if !client_map.contains_key(&client_id) {
                        client_map.insert(client_id.clone(), client_counter);
                        client_counter += 1;
                        
                        // Сохраняем публичный ключ
                        let point = Point { x: client_x, y: U512::zero() };
                        match client_counter - 1 {
                            0 => data.part1_public_key = Some(point),
                            1 => data.part2_public_key = Some(point),
                            2 => data.sum_public_key = Some(point),
                            _ => {}
                        }
                    }
                    
                    // Извлекаем U512 точки
                    if let Some(equal_idx) = line.find("= U512([") {
                        let point_str = &line[equal_idx..];
                        if let Some(point_x) = parse_u512_from_str(point_str) {
                            let point = Point { x: point_x, y: U512::zero() };
                            if let Some(&client_idx) = client_map.get(&client_id) {
                                match client_idx {
                                    0 => data.mvx1_vp = Some(point),
                                    1 => data.mvx2_vp = Some(point),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Парсинг matrix_controller_point
        if line.contains("matrix_controller_point = U512([") {
            if let Some(point_x) = parse_u512_from_str(&line) {
                data.mc = Some(Point { x: point_x, y: U512::zero() });
            }
        }
        
        // Парсинг p1
        if line.contains("p1 = U512([") {
            if let Some(point_x) = parse_u512_from_str(&line) {
                data.p1 = Some(Point { x: point_x, y: U512::zero() });
            }
        }
        
        // Парсинг p2
        if line.contains("p2 = U512([") {
            if let Some(point_x) = parse_u512_from_str(&line) {
                data.p2 = Some(Point { x: point_x, y: U512::zero() });
            }
        }
    }
    
    Ok(data)
}

fn main() -> io::Result<()> {
    let path = "/home/vs/Projects/welsib-independent/welsib-smpc/example/debug_server.txt";
    let data = parse_debug_log(path)?;
    
    // Выводим результаты в формате для несетевой версии
    println!("=== Результаты парсинга ===");
    
    if let Some(p) = &data.part1_public_key {
        println!("let part1_public_key = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.part2_public_key {
        println!("\nlet part2_public_key = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.sum_public_key {
        println!("\nlet sum_public_key = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.mx1 {
        println!("\nlet mx1 = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.mx2 {
        println!("\nlet mx2 = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.my {
        println!("\nlet my = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.mc {
        println!("\nlet mc = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.mvx1 {
        println!("\nlet mvx1 = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.mvx2 {
        println!("\nlet mvx2 = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.rvyp {
        println!("\nlet rvyp = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.mvx1_vp {
        println!("\nlet mvx1_vp = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.mvx2_vp {
        println!("\nlet mvx2_vp = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.p1 {
        println!("\nlet p1 = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    if let Some(p) = &data.p2 {
        println!("\nlet p2 = Point {{");
        println!("    x: U512::new([{}, {}, {}, {}, {}, {}, {}, {}]),", 
                 p.x.get()[0], p.x.get()[1], p.x.get()[2], p.x.get()[3],
                 p.x.get()[4], p.x.get()[5], p.x.get()[6], p.x.get()[7]);
        println!("    y: U512::zero(),");
        println!("}};");
    }
    
    // Также можно вывести для копирования в несетевую версию
    println!("\n=== Для вставки в несетевую версию ===");
    println!("let (mx1, mx2, my) = (mx1, mx2, my);");
    println!("let (mvx1, mvx2, rvyp) = (mvx1, mvx2, rvyp);");
    println!("let (mvx1_vp, mvx2_vp) = (mvx1_vp, mvx2_vp);");
    println!("let mc = mc;");
    println!("let (p1, p2) = (p1, p2);");
    println!("\n// Проверка:");
    println!("assert_eq!(&p1, &p2);");
    
    Ok(())
}