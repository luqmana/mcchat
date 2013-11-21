use std::io::{Decorator, Reader, Writer};
use std::io::mem::{MemReader, MemWriter};

use util::WriterExtensions;

struct Packet {
    priv in_buf: Option<MemReader>,
    priv out_buf: Option<MemWriter>
}

impl Packet {
    pub fn new_in(buf: ~[u8]) -> Packet {
        Packet {
            in_buf: Some(MemReader::new(buf)),
            out_buf: None
        }
    }

    pub fn new_out(packet_id: i32) -> Packet {
        let mut p = Packet {
            in_buf: None,
            out_buf: Some(MemWriter::new())
        };
        p.write_varint(packet_id);

        p
    }

    pub fn out_buf<'a>(&'a mut self) -> Option<&'a ~[u8]> {
        match self.out_buf {
            Some(ref b) => Some(b.inner_ref()),
            None => None
        }
    }
}

impl Reader for Packet {
    fn read(&mut self, buf: &mut [u8]) -> Option<uint> {
        self.in_buf.read(buf)
    }

    fn eof(&mut self) -> bool {
        self.in_buf.eof()
    }
}

impl Writer for Packet {
    fn write(&mut self, buf: &[u8]) {
        self.out_buf.write(buf);
    }

    fn flush(&mut self) {
        self.out_buf.flush()
    }
}
