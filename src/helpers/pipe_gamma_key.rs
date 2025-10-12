pub struct StdInGammaKeyArguments {
    pub gamma: Vec<u8>,
    pub key: Vec<u8>,
}

impl StdInGammaKeyArguments {
    pub fn read() -> std::io::Result<StdInGammaKeyArguments> {
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer)?;

        // println!("LEN: {:#?}", &buffer.len());
        // println!("BUFFER: {:#?}", &buffer[0..128]);

        if buffer.len() == 128 {
            buffer += "\n";
        }

        if buffer.len() != 129 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Длина строки должна быть 129 символов, где последним стоит символ перевода строки \n",
            ));
        }

        let hexdigits = buffer
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>();
        if hexdigits.len() != 128 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Строка должна состоять из символов 0123456789ABCDFabcdf",
            ));
        }
        // println!("HEX: {:#?}", &hexdigits);

        // For example: let gamma_str = "bc4bbc7e4b47a97d599dbc4bbc7e4b47a97d599dbc4bbc7e4b47a97d599dabba";
        let gamma_str = &hexdigits[0..64];
        let gamma = gamma_str
            .as_bytes()
            .chunks(2)
            .map(|b| u8::from_str_radix(&String::from_utf8(b.to_vec()).unwrap(), 16).unwrap())
            .collect::<Vec<u8>>();
        // println!("Gamma: {:#?}", &gamma.iter().map(|b| format!("{:02x}", b)).collect::<String>());

        // For example: let key_str = "d946b869df58aae3a68fd946b869df58aae3a68fd946b869df58aae3a68fabba";
        let key_str = &hexdigits[64..128];
        let key = key_str
            .as_bytes()
            .chunks(2)
            .map(|b| u8::from_str_radix(&String::from_utf8(b.to_vec()).unwrap(), 16).unwrap())
            .collect::<Vec<u8>>();
        // let key_bytes: [u8; 32] = key.try_into().unwrap();
        // println!("Key: {:#?}", &key_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());

        Ok(StdInGammaKeyArguments { gamma, key })
    }

    pub fn read_list() -> std::io::Result<Vec<StdInGammaKeyArguments>> {
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer)?;

        // println!("LEN: {:#?}", &buffer.len());
        // println!("BUFFER: {:#?}", &buffer[0..128]);

        if buffer.len() < 128 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Некорректная длина строки, где в конце должен стоять символ перевода строки \n",
            ));
        }

        // TODO: проверить за ошибки связанные с отсутствием в конце символа перевода строки \n
        // if buffer.len() == 128 {
        //     buffer += "\n";
        // }

        // if buffer.len() != 129 {
        //     return Err(std::io::Error::new(
        //         std::io::ErrorKind::InvalidInput,
        //         "Длина строки должна быть 129 символов, где последним стоит символ перевода строки \n",
        //     ));
        // }

        let hexdigits = buffer
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>();
        if hexdigits.len() % 128 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Строка должна состоять из символов 0123456789ABCDFabcdf",
            ));
        }
        // println!("HEX: {:#?}", &hexdigits);

        let hexdigits_list: Vec<String> = hexdigits.as_bytes()
            .chunks(128)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect();

        let mut output = vec![];

        for hexdigits_item in hexdigits_list {
            // For example: let gamma_str = "bc4bbc7e4b47a97d599dbc4bbc7e4b47a97d599dbc4bbc7e4b47a97d599dabba";
            let gamma_str = &hexdigits_item[0..64];
            let gamma = gamma_str
                .as_bytes()
                .chunks(2)
                .map(|b| u8::from_str_radix(&String::from_utf8(b.to_vec()).unwrap(), 16).unwrap())
                .collect::<Vec<u8>>();
            // println!("Gamma: {:#?}", &gamma.iter().map(|b| format!("{:02x}", b)).collect::<String>());

            // For example: let key_str = "d946b869df58aae3a68fd946b869df58aae3a68fd946b869df58aae3a68fabba";
            let key_str = &hexdigits_item[64..128];
            let key = key_str
                .as_bytes()
                .chunks(2)
                .map(|b| u8::from_str_radix(&String::from_utf8(b.to_vec()).unwrap(), 16).unwrap())
                .collect::<Vec<u8>>();
            // let key_bytes: [u8; 32] = key.try_into().unwrap();
            // println!("Key: {:#?}", &key_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());
            output.push(StdInGammaKeyArguments { gamma, key });
        }

        Ok(output)
    }
}
