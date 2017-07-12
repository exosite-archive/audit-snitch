#[macro_use] extern crate lazy_static;
extern crate regex;
extern crate libc;
extern crate protobuf;
extern crate chan_signal;
extern crate openssl;
extern crate byteorder;
#[macro_use] extern crate slog;
extern crate slog_term;
extern crate slog_journald;
extern crate toml;
#[macro_use] extern crate serde_derive;
extern crate clap;
extern crate base64;
extern crate curl;

mod ssl_madness;
mod audit;
mod crypto;

use std::{io, thread};

use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::convert::AsRef;
use std::str;

use chan_signal::Signal;
use openssl::ssl;
use clap::{Arg, App, SubCommand};

#[derive(Deserialize)]
struct ServerSpec {
    hostname: String,
    port: u32,
}

#[derive(Deserialize)]
struct Config {
    api_server: ServerSpec,
    sink_server: ServerSpec,
    api_key: String,
    client_cert: String,
    client_key: String,
    ca_cert: String,
    log_file: String,
}

fn write_data<P: AsRef<Path>>(file_path: P, data: &[u8]) -> io::Result<()> {
    let mut f = File::create(file_path)?;
    f.write_all(data)?;
    return Ok(());
}

fn stringify_err<E: Error>(e: E) -> String {
    String::from(e.description())
}

fn provision(config: &Config, id: &str) -> Result<(), String> {
    use curl::easy::{Easy, List};
    use crypto::{KeyType, ECurve};

    let hmac_key = crypto::load_hmac_key(&config.api_key)?;

    let client_key = crypto::generate_client_key(KeyType::Ecdsa(ECurve::Prime256v1))?;
    let key_pem_bytes = match client_key.private_key_to_pem() {
        Ok(pem_vec) => pem_vec,
        Err(openssl_err) => return Err(String::from(openssl_err.description())),
    };
    match write_data(&config.client_key, &key_pem_bytes) {
        Ok(_) => (),
        Err(write_err) => return Err(String::from(write_err.description())),
    };

    let csr = crypto::create_csr(&client_key, &client_key, id)?;
    let csr_pem_bytes = match csr.to_pem() {
        Ok(pem_vec) => pem_vec,
        Err(csr_err) => return Err(String::from(csr_err.description())),
    };
    let csr_sig = crypto::sign_data(&hmac_key, &csr_pem_bytes)?;

    let mut response_bytes = Vec::new();
    let response_status = {
        let mut csr_cursor = io::Cursor::new(csr_pem_bytes);

        let mut easy = Easy::new();
        let url = format!("https://{}:{}/v1/provision", config.api_server.hostname, config.api_server.port);
        let csr_sig_header = format!("CSR-Signature: {}", base64::encode(&csr_sig));
        easy.url(&url).map_err(stringify_err)?;
        easy.cainfo(&config.ca_cert).map_err(stringify_err)?;
        easy.put(true).unwrap();
        let mut headers = List::new();
        headers.append("Content-Type: application/octet-stream").unwrap();
        headers.append(&csr_sig_header).unwrap();
        easy.http_headers(headers).map_err(stringify_err)?;
        {
            let mut transfer = easy.transfer();
            transfer.write_function(|data| {
                response_bytes.write_all(data).unwrap();
                Ok(data.len())
            }).unwrap();
            transfer.read_function(|into| {
                Ok(csr_cursor.read(into).unwrap())
            }).unwrap();
            transfer.perform().map_err(stringify_err)?;
        }
        easy.response_code().map_err(stringify_err)?
    };

    return if response_status == 200 {
        let mut f = match File::create(&config.client_cert) {
            Ok(f) => f,
            Err(create_err) => return Err(String::from(create_err.description())),
        };
        f.write_all(&response_bytes).map_err(stringify_err)?;
        Ok(())
    } else {
        let body_text = match String::from_utf8(response_bytes) {
            Ok(s) => s,
            Err(_) => String::from("UTF8ERROR"),
        };
        Err(format!("Failed to provision: {} => {}", response_status, body_text))
    };
}

fn main() {
    let matches = App::new("audit-snitch")
        .version("1.0")
        .author("Alex Wauck <alexwauck@exosite.com>")
        .about("Reports admin commands to central location")
        .arg(Arg::with_name("config")
             .short("c")
             .long("config")
             .value_name("FILE")
             .takes_value(true)
             .help("Cconfig file (default: /etc/audit-snitch.toml)")
             .global(true)
             .default_value("/etc/audit-snitch.toml"))
        .subcommand(SubCommand::with_name("provision")
                    .about("Provisions this machine (must be able to write to client key/cert paths)")
                    .arg(Arg::with_name("machine_name")
                         .required(true)))
        .get_matches();
    let config: Config = {
        let config_path = matches.value_of("config").unwrap();
        let mut config_file = File::open(config_path).expect(&format!("{} not found!", config_path));
        let mut config_bytes = Vec::new();
        config_file.read_to_end(&mut config_bytes).expect(&format!("Failed to read {}!", config_path));
        toml::from_slice(&config_bytes).expect(&format!("{} is not valid TOML!", config_path))
    };

    if let Some(sc_matches) = matches.subcommand_matches("provision") {
        let machine_name = sc_matches.value_of("machine_name").unwrap();
        match provision(&config, machine_name) {
            Ok(_) => (),
            Err(provision_err) => panic!(provision_err),
        };
        return;
    }

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

    let ssl_ctx = match ssl_madness::create_ssl_context_with_client_cert(&config.client_cert, &config.client_key) {
        Ok(ctx) => ctx,
        Err(ssl_err) => panic!("{:?}", ssl_err),
    };

    let ssl_master = match ssl::Ssl::new(&ssl_ctx) {
        Ok(ssl_m) => ssl_m,
        Err(ssl_err) => panic!("{:?}", ssl_err),
    };

    let sockaddr_spec = format!("{}:{}", config.sink_server.hostname, config.sink_server.port);
    let tcp_conn = match TcpStream::connect(&sockaddr_spec) {
        Ok(tcp_c) => tcp_c,
        Err(tcp_err) => panic!("{:?}", tcp_err),
    };

    let mut ssl_conn = match ssl_master.connect(tcp_conn) {
        Ok(ssl_c) => ssl_c,
        Err(ssl_err) => panic!("{:?}", ssl_err),
    };

    let mut outfile = match File::create(&config.log_file) {
        Ok(f) => f,
        Err(_) => panic!("Failed to open {}!", config.log_file),
    };

    let mut records: HashMap<i32, Box<audit::AuditRecord>> = HashMap::new();

    while should_run {
        println!("Reading header from stdin...");
        let hdr = match audit::read_header(&mut stdin) {
            Ok(hdr_struct) => hdr_struct,
            Err(ioerr) => {
                println!("Failed to read header: {}", ioerr.description());
                break;
            },
        };
        println!("Read header.");
        if hdr.ver != 0 {
            panic!("Unsupported audit version: {}", hdr.ver);
        }
        let msg = match audit::read_message(&mut stdin, hdr.size as usize) {
            Ok(msg_str) => msg_str,
            Err(_) => panic!("Failed to read message!"),
        };
        println!("Read a message!");
        write!(outfile, "{}\n", msg).unwrap();
        let rec = match audit::parse_message(hdr.msg_type, &msg) {
            Err(errstr) => {
                println!("Failed to parse message: {}", errstr);
                continue;
            },
            Ok(rec) => Box::new(rec),
        };
        println!("Parsed the message!");

        println!("Checking records...");
        let rec_id = rec.get_id();
        let contains_key = records.contains_key(&rec_id);
        if contains_key {
            {
                let other = records.get(&rec_id).unwrap();
                match audit::dispatch_audit_event(&mut ssl_conn, &rec, &*other) {
                    Ok(_) => {
                        write!(outfile, "Dispatched event {}\n", rec_id);
                        println!("Dispatched event {}", rec_id);
                    },
                    Err(dispatch_error) => {
                        write!(outfile, "Failed to dispatch event: {}\n", dispatch_error.description());
                        println!("Failed to dispatch event: {}", dispatch_error.description());
                    },
                };
            }
            records.remove(&rec_id);
        } else {
            records.insert(rec_id, rec);
        }
    }
    match ssl_conn.shutdown() {
        Ok(ssl::ShutdownResult::Sent) => match ssl_conn.shutdown() {
            Ok(ssl::ShutdownResult::Received) => println!("SSL connection shut down!"),
            _ => println!("SSL connection only partially shut down.  Screw it!  We're done here!"),
        },
        Ok(ssl::ShutdownResult::Received) => println!("SSL connection shut down!"),
        Err(shutdown_err) => println!("Failed to shut down SSL connection: {}", shutdown_err.description()),
    };
}
