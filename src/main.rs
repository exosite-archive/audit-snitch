#[macro_use] extern crate lazy_static;
extern crate regex;
extern crate libc;
extern crate protobuf;
extern crate chan_signal;
extern crate openssl;
extern crate byteorder;
#[macro_use] extern crate slog;
extern crate slog_term;
#[cfg(journald)] extern crate slog_journald;
extern crate slog_async;
extern crate toml;
#[macro_use] extern crate serde_derive;
extern crate clap;
extern crate base64;
extern crate curl;

mod ssl_madness;
mod audit;
mod crypto;

use std::{io, thread, fmt, str};

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::convert::AsRef;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::sync::mpsc::{sync_channel, Receiver};

use chan_signal::Signal;
use openssl::ssl;
use openssl::error::ErrorStack;
use openssl::ssl::HandshakeError;
use clap::{Arg, App, SubCommand};
use slog::{Logger, LevelFilter, Drain};

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
    debug_logging: bool,
}

fn get_pid() -> i32 {
    unsafe { libc::getpid() as i32 }
}

fn write_data<P: AsRef<Path>>(file_path: P, data: &[u8]) -> io::Result<()> {
    let mut f = File::create(file_path)?;
    f.write_all(data)?;
    return Ok(());
}

#[derive(Debug)]
enum ProvisionError {
    OpenSSL(ErrorStack),
    IO(io::Error),
    Curl(curl::Error),
    Hmac(crypto::HmacLoadError),
    Server(String),
}

impl Error for ProvisionError {
    fn description(&self) -> &str {
        match self {
            &ProvisionError::OpenSSL(ref err) => err.description(),
            &ProvisionError::IO(ref err) => err.description(),
            &ProvisionError::Curl(ref err) => err.description(),
            &ProvisionError::Hmac(ref err) => err.description(),
            &ProvisionError::Server(ref errstr) => &errstr,
        }
    }

    fn cause(&self) -> Option<&Error> {
        match self {
            &ProvisionError::OpenSSL(ref err) => Some(err),
            &ProvisionError::IO(ref err) => Some(err),
            &ProvisionError::Curl(ref err) => Some(err),
            &ProvisionError::Hmac(ref err) => Some(err),
            &ProvisionError::Server(_) => None,
        }
    }
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl std::convert::From<ErrorStack> for ProvisionError {
    fn from(err: ErrorStack) -> Self {
        ProvisionError::OpenSSL(err)
    }
}

impl std::convert::From<io::Error> for ProvisionError {
    fn from(err: io::Error) -> Self {
        ProvisionError::IO(err)
    }
}

impl std::convert::From<curl::Error> for ProvisionError {
    fn from(err: curl::Error) -> Self {
        ProvisionError::Curl(err)
    }
}

impl std::convert::From<crypto::HmacLoadError> for ProvisionError {
    fn from(err: crypto::HmacLoadError) -> Self {
        ProvisionError::Hmac(err)
    }
}

fn provision(config: &Config, id: &str) -> Result<(), ProvisionError> {
    use curl::easy::{Easy, List};
    use crypto::{KeyType, ECurve};

    let hmac_key = crypto::load_hmac_key(&config.api_key)?;

    let client_key = crypto::generate_client_key(KeyType::Ecdsa(ECurve::Prime256v1))?;
    let key_pem_bytes = client_key.private_key_to_pem()?;
    write_data(&config.client_key, &key_pem_bytes)?;

    let csr = crypto::create_csr(&client_key, &client_key, id)?;
    let csr_pem_bytes = csr.to_pem()?;
    let csr_sig = crypto::sign_data(&hmac_key, &csr_pem_bytes)?;

    let mut response_bytes = Vec::new();
    let response_status = {
        let mut csr_cursor = io::Cursor::new(csr_pem_bytes);

        let mut easy = Easy::new();
        let url = format!("https://{}:{}/v1/provision", config.api_server.hostname, config.api_server.port);
        let csr_sig_header = format!("CSR-Signature: {}", base64::encode(&csr_sig));
        easy.url(&url)?;
        easy.cainfo(&config.ca_cert)?;
        easy.put(true).unwrap();
        let mut headers = List::new();
        headers.append("Content-Type: application/octet-stream").unwrap();
        headers.append(&csr_sig_header).unwrap();
        easy.http_headers(headers)?;
        {
            let mut transfer = easy.transfer();
            transfer.write_function(|data| {
                response_bytes.write_all(data).unwrap();
                Ok(data.len())
            }).unwrap();
            transfer.read_function(|into| {
                Ok(csr_cursor.read(into).unwrap())
            }).unwrap();
            transfer.perform()?;
        }
        easy.response_code()?
    };

    return if response_status == 200 {
        let mut f = File::create(&config.client_cert)?;
        f.write_all(&response_bytes)?;
        Ok(())
    } else {
        let body_text = match String::from_utf8(response_bytes) {
            Ok(s) => s,
            Err(_) => String::from("UTF8ERROR"),
        };
        Err(ProvisionError::Server(format!("Failed to provision: {} => {}", response_status, body_text)))
    };
}

fn clean_records(records: &mut HashMap<i32, Box<audit::AuditRecord>>) {
    let now = SystemTime::now();
    let mut ids_to_remove = Vec::new();
    for (id, rec) in records.iter() {
        let insertion_ts = rec.get_insertion_timestamp();
        match now.duration_since(insertion_ts) {
            Ok(duration) => if duration.as_secs() > 10 {
                ids_to_remove.push(id.clone());
            },
            Err(_) => (),
        }
    }
    for id in ids_to_remove {
        records.remove(&id);
    }
}

#[derive(Debug)]
enum ConnectError {
    OpenSSL(ErrorStack),
    IO(io::Error),
    Handshake(HandshakeError<TcpStream>),
}

impl Error for ConnectError {
    fn description(&self) -> &str {
        match self {
            &ConnectError::OpenSSL(ref err) => err.description(),
            &ConnectError::IO(ref err) => err.description(),
            &ConnectError::Handshake(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        match self {
            &ConnectError::OpenSSL(ref err) => Some(err),
            &ConnectError::IO(ref err) => Some(err),
            &ConnectError::Handshake(ref err) => Some(err),
        }
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl std::convert::From<ErrorStack> for ConnectError {
    fn from(err: ErrorStack) -> Self {
        ConnectError::OpenSSL(err)
    }
}

impl std::convert::From<io::Error> for ConnectError {
    fn from(err: io::Error) -> Self {
        ConnectError::IO(err)
    }
}

impl std::convert::From<HandshakeError<TcpStream>> for ConnectError {
    fn from(err: HandshakeError<TcpStream>) -> Self {
        ConnectError::Handshake(err)
    }
}

fn try_connect_ssl(client_cert_path: &str, client_key_path: &str, hostname: &str, port: u32) -> Result<ssl::SslStream<TcpStream>, ConnectError> {
    let ssl_ctx = ssl_madness::create_ssl_context_with_client_cert(client_cert_path, client_key_path)?;
    let ssl_connector = ssl::Ssl::new(&ssl_ctx)?;
    let sockaddr_spec = format!("{}:{}", hostname, port);
    let tcp_conn = TcpStream::connect(&sockaddr_spec)?;

    match ssl_connector.connect(tcp_conn) {
        Ok(ssl_c) => Ok(ssl_c),
        Err(err) => Err(ConnectError::from(err)),
    }
}

fn connect_ssl(logger: &Logger, client_cert_path: &str, client_key_path: &str, hostname: &str, port: u32) -> ssl::SslStream<TcpStream> {
    loop {
        match try_connect_ssl(client_cert_path, client_key_path, hostname, port) {
            Ok(ssl_conn) => return ssl_conn,
            Err(conn_err) => error!(logger, "Failed to connect to {}:{} because {}", hostname, port, conn_err.description()),
        };
    }
}

struct PendingTransfer {
    pub syscall: audit::SyscallRecord,
    pub execve: audit::ExecveRecord,
}

impl PendingTransfer {
    fn from(rec1: audit::AuditRecord, rec2: audit::AuditRecord) -> io::Result<PendingTransfer> {
        use audit::AuditRecord::*;
        let (syscall, execve) = match rec1 {
            Syscall(syscall) => (syscall, match rec2 {
                Execve(execve) => execve,
                Syscall(_) => return Err(io::Error::new(io::ErrorKind::Other, "No execve record found!")),
            }),
            Execve(execve) => (match rec2 {
                Syscall(syscall) => syscall,
                Execve(_) => return Err(io::Error::new(io::ErrorKind::Other, "No syscall record found!")),
            }, execve),
        };

        return Ok(PendingTransfer{
            syscall: syscall,
            execve: execve,
        });
    }
}

struct SslReconnector {
    logger: Logger,
    client_cert_path: String,
    client_key_path: String,
    hostname: String,
    port: u32,
}

impl SslReconnector {
    fn from(logger: &Logger, client_cert_path: &str, client_key_path: &str, hostname: &str, port: u32) -> SslReconnector {
        SslReconnector{
            logger: logger.clone(),
            client_cert_path: String::from(client_cert_path),
            client_key_path: String::from(client_key_path),
            hostname: String::from(hostname),
            port: port,
        }
    }

    fn connect(&self) -> ssl::SslStream<TcpStream> {
        error!(self.logger, "Establishing new connection to {}:{}", self.hostname, self.port);
        connect_ssl(&self.logger, &self.client_cert_path, &self.client_key_path, &self.hostname, self.port)
    }
}

fn shutdown_ssl_connection(mut ssl_conn: ssl::SslStream<TcpStream>) -> Result<(), ssl::Error> {
    match ssl_conn.shutdown() {
        Ok(ssl::ShutdownResult::Sent) => match ssl_conn.shutdown() {
            Ok(ssl::ShutdownResult::Received) => Ok(()),
            Ok(ssl::ShutdownResult::Sent) => Ok(()), // Whatever.
            Err(ssl_err) => Err(ssl_err),
        },
        Ok(ssl::ShutdownResult::Received) => Ok(()),
        Err(ssl_err) => Err(ssl_err),
    }
}

fn send_record(logger: &Logger, ssl_conn: ssl::SslStream<TcpStream>, ssl_reconnector: &SslReconnector, pending: &PendingTransfer) -> ssl::SslStream<TcpStream> {
    let mut new_ssl_conn = ssl_conn;
    let mut attempts = 0;
    if pending.syscall.id != pending.execve.id {
        error!(logger, "send_record received syscall record {} and execve record {} together!  Madness!", pending.syscall.id, pending.execve.id);
        return new_ssl_conn;
    }
    let rec_id = pending.syscall.id;
    loop {
        if attempts > 2 {
            error!(logger, "More than two attempts have been made.  Waiting one minute...");
            thread::sleep(Duration::from_millis(1000 * 60));
        } else if attempts > 5 {
            error!(logger, "More than five attempts have been made.  Giving up!");
            return new_ssl_conn;
        }
        match audit::dispatch_audit_event(&mut new_ssl_conn, &pending.syscall, &pending.execve) {
            Ok(_) => {
                debug!(logger, "Dispatched event {}", rec_id);
                return new_ssl_conn;
            },
            Err(dispatch_error) => {
                error!(logger, "Failed to dispatch event: {}", dispatch_error.description());
                error!(logger, "Restarting connection...");
                match shutdown_ssl_connection(new_ssl_conn) {
                    Ok(_) => debug!(logger, "SSL connection shut down."),
                    Err(ssl_err) => {
                        error!(logger, "Failed to shut down SSL connection: {}", ssl_err.description());
                        error!(logger, "Proceeding anyway...");
                    },
                };
                new_ssl_conn = ssl_reconnector.connect();
                error!(logger, "Connection re-established.  Trying to send event {} again...", rec_id);
                attempts += 1;
            },
        };
    }
}

fn record_sender(logger: Logger, ssl_reconnector: SslReconnector, recv: Receiver<PendingTransfer>) {
    let mut ssl_conn = ssl_reconnector.connect();
    loop {
        match recv.recv() {
            Ok(pending) => {
                ssl_conn = send_record(&logger, ssl_conn, &ssl_reconnector, &pending);
            },
            // If the other end closes, we're done.
            Err(_) => break,
        }
    }
    match shutdown_ssl_connection(ssl_conn) {
        Ok(_) => debug!(logger, "SSL connection shut down."),
        Err(ssl_err) => {
            error!(logger, "Failed to shut down SSL connection: {}", ssl_err.description());
            error!(logger, "Proceeding anyway...");
        },
    };
}

#[cfg(journald)]
fn make_journald_logger(min_log_level: slog::Level) -> Logger {
    let drain = slog_journald::JournaldDrain.ignore_res();
    let drain = LevelFilter::new(drain, min_log_level).fuse();
    Logger::root(drain, o!("pid" => get_pid()))
}

#[allow(unused_variables)]
#[cfg(not(journald))]
fn make_journald_logger(min_log_level: slog::Level) -> Logger {
    panic!("journald is not supported by this build!")
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

    let min_log_level = if config.debug_logging {
        slog::Level::Debug
    } else {
        slog::Level::Info
    };
    let logger = if config.log_file == "journald" {
        make_journald_logger(min_log_level)
    } else {
        let outfile = match OpenOptions::new()
            .create(true)
            .truncate(false)
            .append(true)
            .open(&config.log_file) {
                Ok(f) => f,
                Err(_) => panic!("Failed to open {}!", config.log_file),
            };
        let decorator = slog_term::PlainDecorator::new(outfile);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        let drain = LevelFilter::new(drain, min_log_level).fuse();
        Logger::root(drain, o!("pid" => get_pid()))
    };

    if let Some(sc_matches) = matches.subcommand_matches("provision") {
        let machine_name = sc_matches.value_of("machine_name").unwrap();
        match provision(&config, machine_name) {
            Ok(_) => (),
            Err(provision_err) => {
                crit!(logger, "{:?}", provision_err);
                panic!(provision_err);
            },
        };
        info!(logger, "Got a certificate from the server");
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

    let (sender, receiver) = sync_channel(100);
    let record_sender_logger = logger.clone();
    let sender_thread = thread::spawn(move || {
        let ssl_reconnector = SslReconnector::from(&record_sender_logger, &config.client_cert, &config.client_key, &config.sink_server.hostname, config.sink_server.port);
        record_sender(record_sender_logger, ssl_reconnector, receiver);
    });

    let mut records: HashMap<i32, Box<audit::AuditRecord>> = HashMap::new();
    let mut last_clean = UNIX_EPOCH;
    while should_run {
        let now = SystemTime::now();
        let time_since_clean = match now.duration_since(last_clean) {
            Ok(duration) => duration.as_secs(),
            // If negative time appears to have passed since the last
            // clean, force a new clean.
            Err(_) => 1000000,
        };
        if time_since_clean > 60 {
            clean_records(&mut records);
            last_clean = now;
        }

        let hdr = match audit::read_header(&mut stdin) {
            Ok(hdr_struct) => hdr_struct,
            Err(ioerr) => {
                error!(logger, "Failed to read header: {}", ioerr.description());
                break;
            },
        };
        if hdr.ver != 0 {
            crit!(logger, "Unsupported audit version: {}", hdr.ver);
            panic!("Unsupported audit version: {}", hdr.ver);
        }
        let msg = match audit::read_message(&mut stdin, hdr.size as usize) {
            Ok(msg_str) => msg_str,
            Err(_) => {
                // I'm not sure if we should log a failure or just die in this case.
                error!(logger, "Failed to read message!");
                continue;
            },
        };
        let rec = match audit::parse_message(hdr.msg_type, &msg) {
            Err(err) => match err {
                audit::MessageParseError::UnknownType(_) => continue,
                _ => {
                    error!(logger, "Failed to parse message: {}", err.long_description());
                    continue;
                },
            },
            Ok(rec) => Box::new(rec),
        };

        let rec_id = rec.get_id();
        let contains_key = records.contains_key(&rec_id);
        if contains_key {
            {
                let other = records.remove(&rec_id).unwrap();
                match PendingTransfer::from(*rec, *other) {
                    Ok(pt) => match sender.send(pt) {
                        Ok(_) => (),
                        Err(wtf) => error!(logger, "Failed to send internally; this should never happen: {}", wtf),
                    },
                    Err(wtf) => error!(logger, "Failed to construct PendingTransfer; this should never happen: {}", wtf),
                };
            }
        } else {
            records.insert(rec_id, rec);
        }
    }
    drop(sender);
    match sender_thread.join() {
        Ok(_) => (),
        Err(err) => error!(logger, "Sender thread crashed: {:?}", err),
    };
}
