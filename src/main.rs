#[macro_use] extern crate lazy_static;
extern crate regex;
extern crate libc;
extern crate protobuf;
extern crate chan_signal;
extern crate openssl;
extern crate byteorder;

mod ssl_madness;
mod audit;

use std::{io, thread};

use std::fs::File;
use std::io::Write;
use std::net::TcpStream;
use std::collections::HashMap;
use std::error::Error;

use chan_signal::Signal;
use openssl::ssl;

fn main() {
    let mut stdin = io::stdin();
    let mut should_run = true;

    thread::spawn(move || {
        let signal = chan_signal::notify(&[Signal::TERM]);
        loop {
            match signal.recv() {
                Some(_) => {
                    should_run = false;
                },
                None => (),
            };
        }
    });

    let ssl_ctx = match ssl_madness::create_ssl_context_with_client_cert("/tmp/client.crt", "/tmp/client.key") {
        Ok(ctx) => ctx,
        Err(ssl_err) => panic!("{:?}", ssl_err),
    };

    let ssl_master = match ssl::Ssl::new(&ssl_ctx) {
        Ok(ssl_m) => ssl_m,
        Err(ssl_err) => panic!("{:?}", ssl_err),
    };

    let tcp_conn = match TcpStream::connect("localhost:8443") {
        Ok(tcp_c) => tcp_c,
        Err(tcp_err) => panic!("{:?}", tcp_err),
    };

    let mut ssl_conn = match ssl_master.connect(tcp_conn) {
        Ok(ssl_c) => ssl_c,
        Err(ssl_err) => panic!("{:?}", ssl_err),
    };

    let mut outfile = match File::create("/tmp/foobar.log") {
        Ok(f) => f,
        Err(_) => panic!("Failed to open /tmp/foobar.log!"),
    };

    let mut records: HashMap<i32, Box<audit::AuditRecord>> = HashMap::new();

    while should_run {
        let hdr = match audit::read_header(&mut stdin) {
            Ok(hdr_struct) => hdr_struct,
            Err(_) => {
                break;
            },
        };
        if hdr.ver != 0 {
            panic!("Unsupported audit version: {}", hdr.ver);
        }
        //println!("Message size: {}", hdr.size);
        let msg = match audit::read_message(&mut stdin, hdr.size as usize) {
            Ok(msg_str) => msg_str,
            Err(_) => panic!("Failed to read message!"),
        };
        write!(outfile, "{}\n", msg).unwrap();
        let rec = match audit::parse_message(hdr.msg_type, &msg) {
            None => continue,
            Some(rec) => Box::new(rec),
        };

        let rec_id = rec.get_id();
        let contains_key = records.contains_key(&rec_id);
        if contains_key {
            {
                let other = records.get(&rec_id).unwrap();
                match audit::dispatch_audit_event(&mut ssl_conn, &rec, &*other) {
                    Ok(_) => (),
                    Err(dispatch_error) => {
                        write!(outfile, "Failed to dispatch event: {}\n", dispatch_error.description());
                    },
                };
            }
            records.remove(&rec_id);
        } else {
            records.insert(rec_id, rec);
        }
    }
}
