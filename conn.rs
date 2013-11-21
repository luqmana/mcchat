use extra::json;

use std::task;
use std::{comm, io};
use std::io::{io_error, Reader, Writer};
use std::io::buffered::BufferedReader;
use std::io::net::addrinfo;
use std::io::net::tcp::TcpStream;
use std::io::net::ip::SocketAddr;
use std::io::process;
use std::rand;
use std::rand::Rng;
use std::str;

use crypto;
use json::ExtraJSON;
use packet::Packet;
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
        self.write_packet(Packet::new_out(0x0));

        // and read back the response
        let (packet_id, mut packet) = self.read_packet();

        // Make sure we got the right response
        assert_eq!(packet_id, 0x0);

        println(packet.read_string());
    }

    pub fn run(mut self) {

        // If the server is in online-mode
        // we need to do authentication and
        // enable encryption
        self.login();

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
                } else if msg.len() > 100 {
                    println!("Message too long.");
                    continue;
                }

                // Send the message!
                let mut p = Packet::new_out(0x1);
                p.write_string(msg);
                self.write_packet(p);
            }

            // Read in and handle a packet
            let (packet_id, mut packet) = self.read_packet();
            self.handle_message(packet_id, &mut packet);
        }
    }

    fn handle_message(&mut self, packet_id: i32, packet: &mut Packet) {
        // Keep Alive
        if packet_id == 0x0 {
            let x = packet.read_be_i32();

            // Need to respond
            let mut resp = Packet::new_out(0x0);
            resp.write_be_i32(x);
            self.write_packet(resp);

        // Chat Message
        } else if packet_id == 0x2 {
            let json = packet.read_string();
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
        let (mut packet_id, mut packet) = self.read_packet();

        if packet_id == 0x1 {
            // Encryption Request
            // online-mode = true

            self.enable_encryption(&mut packet);

            // Read the next packet...
            let (pi, p) = self.read_packet();
            packet_id = pi;
            packet = p;
        }

        // Login Success
        assert_eq!(packet_id, 0x2);
        let uuid = packet.read_string();
        let username = packet.read_string();

        debug!("UUID: {}", uuid);
        debug!("Username: {}", username);
    }

    fn enable_encryption(&mut self, packet: &mut Packet) {

        // Get all the data from the Encryption Request packet
        let server_id = packet.read_string();
        let key_len = packet.read_be_i16();
        let public_key = packet.read_bytes(key_len as uint);
        let token_len = packet.read_be_i16();
        let verify_token = packet.read_bytes(token_len as uint);

        // Server's public key
        let pk = crypto::RSAPublicKey::from_bytes(public_key).unwrap();

        // Generate random 16 byte key
        let mut key = [0u8, ..16];
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
        self.authenticate(hash);

        // Create Encryption Response Packet
        let mut erp = Packet::new_out(0x1);

        // Write encrypted shared secret
        erp.write_be_i16(ekey.len() as i16);
        erp.write(ekey);

        // Write encrypted verify token
        erp.write_be_i16(etoken.len() as i16);
        erp.write(etoken);

        // Send
        self.write_packet(erp);

        // Create AES cipher with shared secret
        let aes = crypto::AES::new(key.to_owned(), key.to_owned()).unwrap();

        // Get the plain TCP stream
        let sock = match self.sock.take_unwrap() {
            Plain(s) => s,
            _ => fail!("Expected plain socket!")
        };

        // and wwrap it in an AES Stream
        let sock = crypto::AesStream::new(sock, aes);

        // and put the new encrypted stream back
        // everything form this point is encrypted
        self.sock = Some(Encrypted(sock));

    }


    fn authenticate(&mut self, hash: ~str) {
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
        write!(p.io[0].get_mut_ref() as &mut Writer, r#"
            \{
                "agent": \{
                    "name": "Minecraft",
                    "version": 1
                \},
                "username": "{}",
                "password": "{}"
            \}"#, "USER", "PASS"); // XXX: Don't hardcode these...
        p.io[0] = None;

        // read response
        let out = p.io[1].get_mut_ref().read_to_end();
        let out = str::from_utf8(out);
        debug!("Got - {}", out);

        let json = ExtraJSON::new(json::from_str(out).unwrap());
        let token = json["accessToken"].string();
        let profile = json["selectedProfile"]["id"].string();

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
        write!(p.io[0].get_mut_ref() as &mut Writer, r#"
            \{
                "accessToken": "{}",
                "selectedProfile": "{}",
                "serverId": "{}"
            \}"#, token, profile, hash);
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

    fn write_packet(&mut self, mut p: Packet) {
        // Get the actual buffer
        let buf = p.out_buf().unwrap();

        // Write out the packet length
        self.sock.write_varint(buf.len() as i32);

        // and the actual payload
        self.sock.write(*buf);
    }

    fn read_packet(&mut self) -> (i32, Packet) {
        // Read the packet length
        let len = self.sock.read_varint();

        // Now the payload
        let buf = self.sock.read_bytes(len as uint);

        let mut p = Packet::new_in(buf);

        // Get the packet
        let id = p.read_varint();

        (id, p)
    }

    fn send_handshake(&mut self, login: bool) {
        let mut p = Packet::new_out(0x0);

        // Protocol Version
        p.write_varint(4);

        // Server host
        p.write_string(self.host);

        // Server port
        p.write_be_u16(self.addr.port);

        // State
        // 1 - status, 2 - login
        p.write_varint(if login { 2 } else { 1 });

        self.write_packet(p);
    }

    fn send_username(&mut self) {
        let mut p = Packet::new_out(0x0);
        p.write_string(self.name);

        self.write_packet(p);
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
