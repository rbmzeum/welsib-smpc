use std::net::TcpStream;
use std::io::{Read, Write};

pub struct WelsibStream {
    pub tcp_stream: Option<TcpStream>,
}

impl WelsibStream {
    pub fn read(&mut self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 8*1024]; // 8Kb
        if self.tcp_stream.is_some() {
            match self.tcp_stream {
                Some(ref mut tcp_stream) => match tcp_stream.read(&mut buf) {
                    Ok(_result) => Some(buf.to_vec()),
                    Err(e) => {
                        // eprintln!("TcpStream error: {:#?}", e);
                        None
                    }
                },
                None => None,
            }
        } else {
            None
        }
    }

    pub fn write(&mut self, bytes: &Vec<u8>) -> std::io::Result<()> {
        if self.tcp_stream.is_some() {
            match self.tcp_stream {
                Some(ref mut tcp_stream) => {
                    tcp_stream.write_all(bytes.as_slice())?;
                    tcp_stream.flush()?;
                }
                None => {}
            }
        };
        Ok(())
    }
}
