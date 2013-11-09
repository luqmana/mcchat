use extra::json;

use std::rt::io::{Reader, Writer};
use std::{str, vec};

pub trait WriterExtensions: Writer {
    fn write_varint(&mut self, mut x: i32) {
        let mut buf = [0u8, ..10];
        let mut i = 0;
        if x < 0 {
            x = x + (1 << 32);
        }
        while x >= 0x80 {
            buf[i] = (x & 0x7F) as u8 | 0x80;
            x = x >> 7;
            i = i + 1;
        }
        buf[i] = x as u8;

        self.write(buf.slice_to(i + 1));
    }

    fn write_string(&mut self, s: &str) {
        self.write_varint(s.len() as i32);
        self.write(s.as_bytes());
    }
}

impl<T: Writer> WriterExtensions for T {}

pub trait ReaderExtensions: Reader {
    fn read_varint(&mut self) -> i32 {
        let (mut total, mut shift, mut val) = (0, 0, 0x80);

        while (val & 0x80) != 0 {
            val = self.read_u8() as i32;
            total = total | ((val & 0x7F) << shift);
            shift = shift + 7;
        }

        if (total & (1 << 31)) != 0 {
            total = total - (1 << 32);
        }

        total
    }

    fn read_string(&mut self) -> ~str {
        let len = self.read_varint();
        let mut buf = vec::from_elem(len as uint, 0u8);
        self.read(buf);

        str::from_utf8_owned(buf)
    }
}

impl<T: Reader> ReaderExtensions for T {}

pub fn maybe_print_message(j: json::Json) {
    match j {
        json::Object(~o) => {
            let t = match o.find(&~"translate") {
                Some(&json::String(ref s)) => s.clone(),
                _ => return
            };

            if "chat.type.text" == t {
                match o.find(&~"with") {
                    Some(&json::List(ref l)) => {
                        let user = match l[0] {
                            json::Object(ref v) => {
                                match v.find(&~"text") {
                                    Some(&json::String(ref s)) => s.clone(),
                                    _ => return
                                }
                            }
                            _ => return
                        };

                        let msg = match l[1] {
                            json::String(ref s) => s.clone(),
                            _ => return
                        };

                        println!("<{}> {}", user, msg);
                    }
                    _ => {}
                }
            } else if "chat.type.announcement" == t {
                match o.find(&~"with") {
                    Some(&json::List(ref l)) => {
                        match l[1] {
                            json::Object(ref v) => {
                                match v.find(&~"extra") {
                                    Some(&json::List(ref l)) => {
                                        let msg = match l[0] {
                                            json::String(ref s) => s.clone(),
                                            _ => return
                                        };
                                        println!("[Server] {}", msg);
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}
