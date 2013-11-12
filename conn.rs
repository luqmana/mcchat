use extra::json;

use std::task;
use std::rt::{comm, io};
use std::rt::io::{io_error, Decorator, Reader, Writer};
use std::rt::io::buffered::BufferedReader;
use std::rt::io::mem::{MemReader, MemWriter};
use std::rt::io::net::tcp::TcpStream;
use std::rt::io::net::ip::SocketAddr;
use std::vec;

use crypto;
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

    pub fn status(&mut self) {

        self.send_handshake(false);

        // Send the status request
        self.write_packet(0x0, |_, _| ());

        // and read back the response
        do self.read_packet |packet_id, _, r| {
            assert_eq!(packet_id, 0x0);

            println(r.read_string());
        }

    }

    pub fn run(mut self) {

        self.send_handshake(true);
        self.send_username();

        do self.read_packet |packet_id, _, r| {
            // Encryption Request
            if packet_id == 0x1 {

                let server_id = r.read_string();
                let key_len = r.read_be_i16();
                let public_key = r.read_bytes(key_len as uint);
                let token_len = r.read_be_i16();
                let verify_token = r.read_bytes(token_len as uint);

                debug!("Server ID: {}", server_id);
                debug!("Key Len: {}", key_len);
                debug!("Key: {:?}", public_key);
                debug!("Token Len: {}", token_len);
                debug!("Token: {:?}", verify_token);

                let pk = crypto::RSAPublicKey::from_bytes(public_key).unwrap();

            // Login Success
            } else if packet_id == 0x2 {
                let uuid = r.read_string();
                debug!("UUID: {}", uuid);

                let username = r.read_string();
                debug!("Username: {}", username);
            }

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
            while msgs.peek() {
                let msg = msgs.recv();
                if msg.trim().is_empty() {
                    continue;
                } else if msg.len() > 300 {
                    println!("Message too long.");
                    continue;
                }

                // Send the message!
                do self.write_packet(0x1) |_, w| {
                    // Message
                    w.write_string(msg);
                }
            }

            do self.read_packet |packet_id, conn, r| {

                // Keep Alive
                if packet_id == 0x0 {
                    let x = r.read_be_i32();

                    // Need to respond
                    do conn.write_packet(0x0) |_, w| {
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
        rtask.supervised();
        do rtask.spawn_with(chan) |chan| {
            println("Type message and then [ENTER] to send:");

            let mut stdin = BufferedReader::new(io::stdin());
            while !stdin.eof() {
                chan.send(stdin.read_line().unwrap());
            }
        }

        port
    }

    fn write_packet(&mut self, id: i32, f: &fn(&mut Connection, &mut MemWriter)) {
        // Create a buffer that we'll write to in memory
        // that way we can determine the total packet length
        let mut buf = MemWriter::new();

        // Write out the packet id
        buf.write_varint(id);

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

    fn read_packet(&mut self, f: &fn(i32, &mut Connection, &mut MemReader)) {
        // Read the packet length
        let len = self.sock.read_varint();

        // Now the payload
        let mut buf = vec::from_elem(len as uint, 0u8);
        self.sock.read(buf);

        // Let's put it in a Reader
        // to more easily interact with the data
        let mut buf = MemReader::new(buf);

        // Get the packet id and let the caller do their thing
        let id = buf.read_varint();
        f(id, self, &mut buf);
    }

    fn send_handshake(&mut self, login: bool) {
        do self.write_packet(0x0) |this, w| {
            // Protocol Version
            w.write_varint(4);

            // Server host
            w.write_string(this.addr.ip.to_str());

            // Server port
            w.write_be_u16(this.addr.port);

            // State
            // 1 - status, 2 - login
            w.write_varint(if login { 2 } else { 1 });
        }
    }

    fn send_username(&mut self) {
        do self.write_packet(0x0) |this, w| {
            // User name
            w.write_string(this.name);
        }
    }
}
