extern mod extra;

use extra::getopts::groups;
use std::os;
use std::io::timer::Timer;

mod conn;
mod crypto;
mod util;

static DEFAULT_NAME: &'static str = "cmc-bot";
static DEFAULT_HOST: &'static str = "127.0.0.1";
static DEFAULT_PORT: u16          = 6660;

/// Print out the usage message.
fn usage(prog: &str, opts: &[groups::OptGroup]) {
    let message = format!("Usage: {} [OPTIONS]", prog);
    println(groups::usage(message, opts));
}

fn main() {
    let args = os::args();
    let opts = [
        groups::optflag("h", "help", "Display this message"),
        groups::optopt("s", "server", "Minecraft server host", "HOST"),
        groups::optopt("p", "port", "Minecraft server port", "PORT"),
        groups::optopt("n", "name", "Username to use.", "NAME"),
        groups::optflag("c", "status", "Get info about the server."),
        groups::optflag("r", "reconnect", "Try to reconnect on some failures."),
        groups::optflag("k", "key", "generate some keys")
    ];
    let matches = match groups::getopts(args.tail(), opts) {
        Ok(m) => m,
        Err(e) => fail!(e.to_err_msg())
    };

    // Should we print out the usage message?
    if matches.opt_present("help") {
        usage(args[0], opts);
        return;
    }

    if matches.opt_present("key") {
        let r = crypto::RSAKeyPair::new(1024, 3).unwrap();
        println!("{}", r.to_str());
        let s = "rsa test data";
        println!("unencrpyted: {}", s);
        let e = r.encrypt(s.as_bytes()).unwrap();
        println!("encrypted: {:?}", e);
        let d = r.decrypt(e).unwrap();
        println!("decrypted: {}", std::str::from_utf8(d));

        let pk = crypto::RSAPublicKey::from_bytes(r.pub_key.to_bytes()).unwrap();
        let e = pk.encrypt(s.as_bytes()).unwrap();
        println!("encrypted (sep): {:?}", e);
        let d = r.decrypt(e).unwrap();
        println!("decrypted: {}", std::str::from_utf8(d));

        let aes = crypto::AES::new(~[1, ..16], ~[2, ..16]).unwrap();

        let s = "aes test data";
        println!("unecrypted: [{}] {}", s.len(), s);
        let e = aes.encrypt(s.as_bytes()).unwrap();
        println!("encrypted: [{}] {:?}", e.len(), e);
        let d = aes.decrypt(e).unwrap();
        println!("decrypted: {}", std::str::from_utf8(d));

        let s = "f".repeat(2);
        println!("unecrypted: [{}] {}", s.len(), s);
        let e = aes.encrypt(s.as_bytes()).unwrap();
        println!("encrypted: [{}] {:?}", e.len(), e);
        let d = aes.decrypt(e).unwrap();
        println!("decrypted: {}", std::str::from_utf8(d));

        let s = "this should be a fairly longish string that is pretty long. long.";
        println!("unecrypted: [{}] {}", s.len(), s);
        let e = aes.encrypt(s.as_bytes()).unwrap();
        println!("encrypted: [{}] {:?}", e.len(), e);
        let d = aes.decrypt(e).unwrap();
        println!("decrypted: {}", std::str::from_utf8(d));
        return;
    }

    let status = matches.opt_present("status");
    let name = matches.opt_str("name").unwrap_or(DEFAULT_NAME.to_owned());
    let host = matches.opt_str("server").unwrap_or(DEFAULT_HOST.to_owned());
    let port = matches.opt_str("port").map_default(DEFAULT_PORT, |x| from_str(x).expect("invalid port"));
    let reconn = matches.opt_present("reconnect");

    serve(name, host, port, status, reconn);
}

fn serve(name: &str, host: &str, port: u16, status: bool, reconn: bool) {
    do std::io::io_error::cond.trap(|e| {
        if reconn {
            println!("Oops, something happened. Will reconnect in 5 seconds...");

            let mut timer = Timer::new().unwrap();
            timer.sleep(5000);

            serve(name, host, port, status, reconn);
        } else {
            fail!(e.to_str());
        }
    }).inside {
        // And now we're off to the races!
        match conn::Connection::new(name.to_owned(), host.to_owned(), port) {
            Ok(ref mut c) if status => c.status(),
            Ok(c) => c.run(),
            Err(e) => fail!("Unable to connect to server: {}.", e)
        }
    }
}
