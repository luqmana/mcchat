use std::io::{MemReader, MemWriter, Reader, Writer};

use util::{Either, Left, Right};
use util::WriterExtensions;

/**
 * The Packet struct has a type parameter that isn't used in any
 * of it's field (i.e. a phantom type). We use it to only implement
 * certain methods for certain kinds of packets. This works since
 * the struct itself is private and the only way to get a Packet is
 * through one of two static methods: `new_in` and `new_out`.
 *
 * Packet<In> is basically just a wrapper around some buffer. It
 * represents a complete packet that we've read in. We also
 * implement the Reader trait to make it more convenient to
 * access the data it encompasses.
 *
 * Packet<Out> represents a buffer we can write to as we build
 * up a complete packet. It implements the Writer trait so we can
 * use all those convenient methods.
 */

enum In {}
enum Out {}

pub type InPacket = Packet<In>;
pub type OutPacket = Packet<Out>;

pub struct Packet<T> {
    priv buf: Either<MemReader, MemWriter>
}

impl Packet<In> {
    pub fn new_in(buf: ~[u8]) -> Packet<In> {
        Packet {
            buf: Left(MemReader::new(buf))
        }
    }
}

impl Packet<Out> {
    pub fn new_out(packet_id: i32) -> Packet<Out> {
        let mut p = Packet {
            buf: Right(MemWriter::new())
        };
        p.write_varint(packet_id);

        p
    }

    pub fn buf(self) -> ~[u8] {
        self.buf.unwrap_right().unwrap()
    }
}

impl Reader for Packet<In> {
    fn read(&mut self, buf: &mut [u8]) -> Option<uint> {
        match self.buf {
            Left(ref mut r) => r.read(buf),
            Right(..) => unreachable!()
        }
    }
}

impl Writer for Packet<Out> {
    fn write(&mut self, buf: &[u8]) {
        match self.buf {
            Left(..) => unreachable!(),
            Right(ref mut w) => w.write(buf)
        }
    }

    fn flush(&mut self) {
        match self.buf {
            Left(..) => unreachable!(),
            Right(ref mut w) => w.flush()
        }
    }
}
