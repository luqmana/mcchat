use extra::json;

use std::task;
use std::{comm, io};
use std::io::{io_error, Decorator, Reader, Writer};
use std::io::buffered::BufferedReader;
use std::io::mem::{MemReader, MemWriter};
use std::io::net::addrinfo;
use std::io::net::tcp::TcpStream;
use std::io::net::ip::SocketAddr;
use std::io::process;
use std::rand;
use std::rand::Rng;
use std::str;

use crypto;
use util;
use util::{ReaderExtensions, WriterExtensions};

enum Sock {
    Plain(TcpStream),
    Encrypted(crypto::AesStream<TcpStream>)
}

struct Connection {
    addr: SocketAddr,
    host: ~str,
    sock: Option<Sock>,
    name: ~str
}

impl Connection {
    pub fn new(name: ~str, host: ~str, port: u16) -> Result<Connection, ~str> {
        let addr = match addrinfo::get_host_addresses(host) {
            Some(a) => a[0],
            None => return Err(~"unable to resolve host address")
        };
        let addr = SocketAddr { ip: addr, port: port };

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
            host: host,
            sock: Some(Plain(sock)),
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

        // If the server is in online-mode
        // we need to do authentication and
        // enable encryption
        self.login();

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

            // Read in and handle a packet
            self.read_packet(|p, c, r| c.handle_message(p, r));
        }
    }

    fn handle_message(&mut self, packet_id: i32, r: &mut MemReader) {
        // Keep Alive
        if packet_id == 0x0 {
            let x = r.read_be_i32();

            // Need to respond
            do self.write_packet(0x0) |_, w| {
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

    fn login(&mut self) {
        self.send_handshake(true);
        self.send_username();

        // Read the next packet and find out whether we need
        // to do authentication and encryption
        do self.read_packet |packet_id, conn, r| {
            let (uuid, username) = if packet_id == 0x1 {
                // Encryption Request
                // online-mode = true

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

                // Server's public key
                let pk = crypto::RSAPublicKey::from_bytes(public_key).unwrap();

                // Generate random 16 byte key
                let mut key = ~[0u8, ..16];
                rand::task_rng().fill_bytes(key);

                // Encrypt shared secret with server's public key
                let ekey = pk.encrypt(key).unwrap();

                // Encrypt verify token with server's public key
                let etoken = pk.encrypt(verify_token).unwrap();

                // Generate the server id hash
                let mut sha1 = crypto::SHA1::new();
                sha1.update(server_id.as_bytes());
                sha1.update(key);
                sha1.update(public_key);
                let hash = sha1.special_digest();

                debug!("Hash: {}", hash);

                // Do client auth
                conn.authenticate(hash);

                // Send the Encryption Response
                do conn.write_packet(0x1) |_, w| {
                    // Send encrypted shared secret
                    w.write_be_i16(ekey.len() as i16);
                    w.write(ekey);

                    // Send encrypted verify token
                    w.write_be_i16(etoken.len() as i16);
                    w.write(etoken);
                }

                // Create AES cipher with shared secret
                let aes = crypto::AES::new(key.clone(), key.clone()).unwrap();

                // Get the plain Tcp stream
                let sock = match conn.sock.take_unwrap() {
                    Plain(s) => s,
                    _ => unreachable!()
                };

                // and wrap it in an AES stream
                // everything from this point is encrypted
                conn.sock = Some(Encrypted(crypto::AesStream::new(sock, aes)));

                // We should get Login Success from the server
                do conn.read_packet |p, _, rr| {
                    assert_eq!(p, 0x2);

                    (rr.read_string(), rr.read_string())
                }

            } else if packet_id == 0x2 {
                // Login Success
                // online-mode = false

                (r.read_string(), r.read_string())
            } else {
                fail!("Unknown packet in login sequence: {:X}", packet_id)
            };

            debug!("UUID: {}", uuid);
            debug!("Username: {}", username);
        }
    }

    fn authenticate(&mut self, hash: ~str) {
        let payload = format!("\
        \\{\
            \"agent\": \\{\
                \"name\": \"Minecraft\",\
                \"version\": 1\
            \\},\
            \"username\": \"{}\",\
            \"password\": \"{}\"\
        \\}", "USER", "PASSWORD"); // XXX: Don't hardcode these...
        let url = ~"https://authserver.mojang.com/authenticate";
        let io = [
            process::CreatePipe(true, false),
            process::CreatePipe(false, true),
        ];
        let c = process::ProcessConfig {
            program: "/usr/bin/curl",
            args: [~"-d", ~"@-", ~"-H", ~"Content-Type:application/json", url],
            env: None,
            cwd: None,
            io: io
        };
        let mut p = process::Process::new(c).unwrap();

        // write json to stdin and close it
        p.io[0].get_mut_ref().write(payload.as_bytes());
        p.io[0] = None;

        // read response
        let out = p.io[1].get_mut_ref().read_to_end();
        let out = str::from_utf8(out);
        debug!("Got - {}", out);

        let json = json::from_str(out).unwrap();
        let token = match json {
            json::Object(ref o) => {
                match o.find(&~"accessToken") {
                    Some(&json::String(ref s)) => s.clone(),
                    _ => ~""
                }
            }
            _ => fail!("")
        };
        let profile = match json {
            json::Object(ref o) => {
                match o.find(&~"selectedProfile") {
                    Some(&json::Object(ref d)) => {
                        match d.find(&~"id") {
                            Some(&json::String(ref s)) => s.clone(),
                            _ => ~""
                        }
                    }
                    _ => ~""
                }
            }
            _ => fail!("")
        };

        let payload = format!("\
        \\{\
            \"accessToken\": \"{}\",\
            \"selectedProfile\": \"{}\",\
            \"serverId\": \"{}\"\
        \\}", token, profile, hash);
        debug!("writing: {}", payload);
        let url = ~"https://sessionserver.mojang.com/session/minecraft/join";
        let io = [
            process::CreatePipe(true, false),
            process::CreatePipe(false, true),
        ];
        let c = process::ProcessConfig {
            program: "/usr/bin/curl",
            args: [~"-d", ~"@-", ~"-H", ~"Content-Type:application/json", url],
            env: None,
            cwd: None,
            io: io
        };
        let mut p = process::Process::new(c).unwrap();

        // write json to stdin and close it
        p.io[0].get_mut_ref().write(payload.as_bytes());
        p.io[0] = None;

        // read response
        let out = p.io[1].get_mut_ref().read_to_end();
        let out = str::from_utf8(out);
        debug!("Got - {}", out);
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

    fn read_packet<T>(&mut self, f: &fn(i32, &mut Connection, &mut MemReader) -> T) -> T {
        // Read the packet length
        let len = self.sock.read_varint();

        // Now the payload
        let buf = self.sock.read_bytes(len as uint);

        // Let's put it in a Reader
        // to more easily interact with the data
        let mut buf = MemReader::new(buf);

        // Get the packet id and let the caller do their thing
        let id = buf.read_varint();
        f(id, self, &mut buf)
    }

    fn send_handshake(&mut self, login: bool) {
        do self.write_packet(0x0) |conn, w| {
            // Protocol Version
            w.write_varint(4);

            // Server host
            w.write_string(conn.host);

            // Server port
            w.write_be_u16(conn.addr.port);

            // State
            // 1 - status, 2 - login
            w.write_varint(if login { 2 } else { 1 });
        }
    }

    fn send_username(&mut self) {
        do self.write_packet(0x0) |conn, w| {
            // User name
            w.write_string(conn.name);
        }
    }
}

impl Reader for Sock {
    fn read(&mut self, buf: &mut [u8]) -> Option<uint> {
        match *self {
            Plain(ref mut s) => s.read(buf),
            Encrypted(ref mut s) => s.read(buf)
        }
    }

    fn eof(&mut self) -> bool {
        match *self {
            Plain(ref mut s) => s.eof(),
            Encrypted(ref mut s) => s.eof()
        }
    }
}

impl Writer for Sock {
    fn write(&mut self, buf: &[u8]) {
        match *self {
            Plain(ref mut s) => s.write(buf),
            Encrypted(ref mut s) => s.write(buf)
        }
    }

    fn flush(&mut self) {
        match *self {
            Plain(ref mut s) => s.flush(),
            Encrypted(ref mut s) => s.flush()
        }
    }
}
