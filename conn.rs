use std::rt::io::{io_error, Reader, Writer};
use std::rt::io::net::tcp::TcpStream;
use std::rt::io::net::ip::SocketAddr;

struct Connection {
    addr: SocketAddr,
    sock: TcpStream
}

impl Connection {
    pub fn new(ip: &str, port: u16) -> Result<Connection, ~str> {
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
            sock: sock
        })
    }

    pub fn run(mut self) {

        self.write_uvarint(29);
        self.send_handshake();

        // Write username
        // Packet length
        self.sock.write_u8(6);
        // Packet ID
        self.sock.write_u8(0);
        self.write_string("ABot");

        let packet_id = self.sock.read_u8();

        debug!("packet_id: {:X}", packet_id);

        // Server should respond to handshake properly
        assert_eq!(packet_id, 0x2F);

    }

    fn send_handshake(&mut self) {
        // Packet ID
        self.sock.write_u8(0x0);

        // Protocol Version
        self.write_uvarint(4);

        // Server host
        let server = self.addr.ip.to_str();
        self.write_string("corn-syrup.uwaterloo.ca");
        //self.write_string(server);

        // Server port
        self.sock.write_be_u16(self.addr.port);

        // Next state
        // 1 - status
        // 2 - login
        self.write_uvarint(2);
    }

    fn write_uvarint(&mut self, mut x: u64) {
        let mut buf = [0u8, ..10];
        let mut i = 0;
        while x >= 0x80 {
            buf[i] = (x as u8) | 0x80;
            x = x >> 7;
            i = i + 1;
        }
        buf[i] = x as u8;

        debug!("writing uvarint {:?}", buf.slice(0, i + 1));
        self.sock.write(buf.slice(0, i + 1));
    }

    fn write_string(&mut self, s: &str) {
        debug!("writing string - {}", s);

        self.write_uvarint(s.len() as u64);
        self.sock.write(s.as_bytes());
    }
}
