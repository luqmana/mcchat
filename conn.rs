use extra::json;

use std::task;
use std::rt::{comm, io};
use std::rt::io::{io_error, Decorator, Reader, Writer};
use std::rt::io::buffered::BufferedReader;
use std::rt::io::mem::{MemReader, MemWriter};
use std::rt::io::net::tcp::TcpStream;
use std::rt::io::net::ip::SocketAddr;
use std::vec;

use util;
use util::{ReaderExtensions, WriterExtensions};

struct Connection {
    addr: SocketAddr,
    sock: TcpStream,
    name: ~str
}

impl Connection {
    pub fn new(name: ~str, ip: &str, port: u16) -> Result<Connection, ~str> {
        let addr: SocketAddr = match from_str(format!("{}:{}", ip, port)) {
            Some(a) => a,
            None => return Err(~"unable to parse given ip/port")
        };

        debug!("Connecting to server at {}.", addr.to_str());
        let mut err = ~"";
        let sock = do io_error::cond.trap(|e| {
            err = format!("{} - {}", e.kind.to_str(), e.desc);
        }).inside {
            TcpStream::connect(addr)
        };

        let sock = match sock {
            Some(s) => s,
            None => return Err(err)
        };

        debug!("Successfully connected to server.");

        Ok(Connection {
            addr: addr,
            sock: sock,
            name: name
        })
    }

    pub fn run(mut self) {

        self.send_handshake();
        self.send_username();

        do self.read_packet |_, r| {
            // Server should've responded with success packet
            assert_eq!(r.read_u8(), 0x2);

            let uuid = r.read_string();
            debug!("UUID: {}", uuid);

            let username = r.read_string();
            debug!("Username: {}", username);
        }

        println("Successfully connected to server.");

        // Get a port to read messages from stdin
        let msgs = self.read_messages();

        // Yay, all good.
        // Now we just loop and read in all the packets we can
        // We don't actually do anything for most of them except
        // for chat and keep alives.
        loop {
            // Got a message in the queue to send?
            if msgs.peek() {
                while msgs.peek() {
                    let msg = msgs.recv();
                    do self.write_packet |_, w| {
                        // Packet ID
                        w.write_varint(0x1);

                        // Message
                        w.write_string(msg);
                    }
                }
            }

            do self.read_packet |this, r| {
                let packet_id = r.read_varint();

                // Keep Alive
                if packet_id == 0x0 {
                    let x = r.read_be_i32();

                    // Need to respond
                    do this.write_packet |_, w| {
                        w.write_varint(0x0);
                        w.write_be_i32(x);
                    }

                // Chat Message
                } else if packet_id == 0x2 {
                    let json = r.read_string();
                    debug!("Got chat message: {}", json);

                    let json = json::from_str(json).unwrap();
                    util::maybe_print_message(json);
                }
            }
        }
    }

    fn read_messages(&self) -> comm::Port<~str> {
        let (port, chan) = comm::stream();

        let mut rtask = task::task();
        rtask.sched_mode(task::SingleThreaded);
        do rtask.spawn_with(chan) |chan| {
            println("Type message and then [ENTER] to send:");

            let mut stdin = BufferedReader::new(io::stdin());
            while !stdin.eof() {
                chan.send(stdin.read_line().unwrap());
            }
        }

        port
    }

    fn write_packet(&mut self, f: &fn(&mut Connection, &mut MemWriter)) {
        // Create a buffer that we'll write to in memory
        // that way we can determine the total packet length
        let mut buf = MemWriter::new();

        // Let the caller do what they need to
        f(self, &mut buf);

        // Now let's write it out to the network

        // Get the actual buffer
        let buf = buf.inner();

        // Write out the packet length
        self.sock.write_varint(buf.len() as i32);

        // and the actual payload
        self.sock.write(buf);
    }

    fn read_packet(&mut self, f: &fn(&mut Connection, &mut MemReader)) {
        // Read the packet length
        let len = self.sock.read_varint();

        // Now the payload
        let mut buf = vec::from_elem(len as uint, 0u8);
        self.sock.read(buf);

        let mut buf = MemReader::new(buf);

        // Let the caller do their thing
        f(self, &mut buf);
    }

    fn send_handshake(&mut self) {
        do self.write_packet |this, w| {
            // Packet ID
            w.write_u8(0x0);

            // Protocol Version
            w.write_varint(4);

            // Server host
            w.write_string(this.addr.ip.to_str());

            // Server port
            w.write_be_u16(this.addr.port);

            // State
            // 1 - status, 2 - login
            w.write_varint(2);
        }
    }

    fn send_username(&mut self) {
        do self.write_packet |this, w| {
            // Packet ID
            w.write_u8(0x0);

            // User name
            w.write_string(this.name);
        }
    }
}
