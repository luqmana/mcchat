#[allow(dead_code)];

extern mod extra;

use extra::getopts::groups;
use std::os;

mod conn;
mod crypto;
mod json;
mod packet;
mod util;

static DEFAULT_NAME: &'static str = "cmc-bot";
static DEFAULT_HOST: &'static str = "127.0.0.1";
static DEFAULT_PORT: u16          = 6660;

/// Print out the usage message.
fn usage(prog: &str, opts: &[groups::OptGroup]) {
    let message = format!("Usage: {} [OPTIONS]", prog);
    std::io::println(groups::usage(message, opts));
}

fn main() {
    let args = os::args();
    let opts = [
        groups::optflag("h", "help", "Display this message"),
        groups::optopt("s", "server", "Minecraft server host", "HOST"),
        groups::optopt("p", "port", "Minecraft server port", "PORT"),
        groups::optopt("n", "name", "Username to use.", "NAME"),
        groups::optflag("c", "status", "Get info about the server."),
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

    let status = matches.opt_present("status");
    let name = matches.opt_str("name").unwrap_or(DEFAULT_NAME.to_owned());
    let host = matches.opt_str("server").unwrap_or(DEFAULT_HOST.to_owned());
    let port = matches.opt_str("port").map_or(DEFAULT_PORT, |x| from_str(x).expect("invalid port"));

    // And now we're off to the races!
    match conn::Connection::new(name, host, port) {
        Ok(ref mut c) if status => c.status(),
        Ok(c) => c.run(),
        Err(e) => fail!("Unable to connect to server: {}.", e)
    }
}
