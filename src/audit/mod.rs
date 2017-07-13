use std::{io, mem, thread, time, i64, i32, fmt};

use std::io::{Read, Write};
use std::time::SystemTime;
use std::collections::HashMap;
use std::error::Error;
use std::slice;
use std::str;

use regex::{Regex, Captures, CaptureMatches};
use protobuf::{CodedOutputStream, Message};
use byteorder::{NetworkEndian, WriteBytesExt};
use self::protos::{AuditTimestamp, ProgramRun, SnitchReport};

use libc;

mod protos;

// From linux/audit.h
pub const AUDIT_SYSCALL: u32 = 1300;
pub const AUDIT_EXECVE: u32 = 1309;
#[allow(dead_code)]
pub const AUDIT_ARCH_64BIT: u32 = 0x80000000;
#[allow(dead_code)]
pub const AUDIT_ARCH_LE: u32 = 0x40000000;

// From linux/elf-em.h
pub const EM_386: u32 = 3;
pub const EM_X86_64: u32 = 62;

// From audit.proto
#[allow(dead_code)]
pub const REPORT_TYPE_ERROR: i32 = 0;
pub const REPORT_TYPE_PROGRAMRUN: i32 = 1;

#[repr(C)]
pub struct audit_dispatcher_header {
    pub ver: libc::uint32_t,
    pub hlen: libc::uint32_t,
    pub msg_type: libc::uint32_t,
    pub size: libc::uint32_t,
}

pub fn read_header<T: Read>(f: &mut T) -> io::Result<audit_dispatcher_header> {
    let read_size = mem::size_of::<audit_dispatcher_header>();
    loop  {
        let mut bytes = Vec::with_capacity(read_size);
        let mut chunk = f.take(read_size as u64);
        let bytes_read = match chunk.read_to_end(&mut bytes) {
            Ok(b) => b,
            Err(ioerr) => match ioerr.kind() {
                io::ErrorKind::WouldBlock => {
                    thread::sleep(time::Duration::from_millis(1000));
                    continue;
                },
                _ => 0,
            },
        };
        if bytes_read < mem::size_of::<audit_dispatcher_header>() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Input stream terminated"));
        }
        unsafe {
            let data_ptr: *const u8 = bytes.as_ptr();
            let hdr_ptr: *const audit_dispatcher_header = data_ptr as *const _;
            let hdr: &audit_dispatcher_header = &*hdr_ptr;
            return Ok(audit_dispatcher_header{
                ver: hdr.ver.clone(),
                hlen: hdr.hlen.clone(),
                msg_type: hdr.msg_type.clone(),
                size: hdr.size.clone(),
            });
        }
    }
}

pub fn read_message<T: Read>(f: &mut T, expected_size: usize) -> io::Result<String> {
    let mut msg_bytes = Vec::with_capacity(expected_size);
    let mut chunk = f.take(expected_size as u64);
    let bytes_read = chunk.read_to_end(&mut msg_bytes)?;
    if bytes_read < expected_size {
        panic!("Not enough message bytes read!");
    }
    return unsafe {
        let msg_slice = slice::from_raw_parts(msg_bytes.as_mut_ptr(), expected_size);
        match str::from_utf8(msg_slice) {
            Ok(valid_str) => Ok(valid_str.to_owned()),
            Err(utferr) => Err(io::Error::new(io::ErrorKind::InvalidData, String::from(utferr.description()))),
        }
    };
}

pub enum SyscallArch {
    Unknown,
    I386,
    Amd64,
}

pub struct SyscallRecord {
    pub id: i32,
    timestamp: i64,
    timestamp_frac: i64,
    inserted_timestamp: SystemTime,
    arch: SyscallArch,
    // This will probably always be 59
    syscall: i32,
    success: bool,
    exit: i32,
    pid: i32,
    ppid: i32,
    uid: i32,
    gid: i32,
    auid: i32,
    euid: i32,
    egid: i32,
    suid: i32,
    sgid: i32,
    fsuid: i32,
    fsgid: i32,
    tty: Option<String>,
    comm: Option<String>,
    exe: Option<String>,
    key: Option<String>,
    subj: Option<String>,
}

// We don't use the timestamp from ExecveRecord right now,
// since the timestamp from the corresponding SyscallRecord
// should be either identical or indistinguishable.  We may
// need it in the future, though (even if only for debugging),
// so let's prevent warnings about it.
#[allow(dead_code)]
pub struct ExecveRecord {
    pub id: i32,
    timestamp: i64,
    timestamp_frac: i64,
    inserted_timestamp: SystemTime,
    args: Vec<String>,
}

pub enum AuditRecord {
    Syscall(SyscallRecord),
    Execve(ExecveRecord),
}

impl AuditRecord {
    pub fn get_id(&self) -> i32 {
        match self {
            &AuditRecord::Syscall(ref rec) => rec.id,
            &AuditRecord::Execve(ref rec) => rec.id,
        }
    }

    pub fn get_insertion_timestamp(&self) -> SystemTime {
        match self {
            &AuditRecord::Syscall(ref rec) => rec.inserted_timestamp,
            &AuditRecord::Execve(ref rec) => rec.inserted_timestamp,
        }
    }
}

fn parse_i32_default(txt: &str, def: i32) -> i32 {
    match i32::from_str_radix(txt, 10) {
        Ok(i) => i,
        Err(_) => def,
    }
}

fn extract_kv_value<'a>(cap: &'a Captures) -> &'a str {
    match cap.name("inner") {
        None => cap.name("value").unwrap().as_str(),
        Some(val) => val.as_str(),
    }
}

struct CommonParseResult<'a> {
    pub timestamp: i64,
    pub timestamp_frac: i64,
    pub id: i32,
    pub kv_iter: CaptureMatches<'a, 'a>,
}

macro_rules! must_get {
    ( $caps:expr, $key: expr ) => (
        $caps.name($key).unwrap().as_str()
    )
}

fn parse_common<'a>(message: &'a str) -> Result<CommonParseResult<'a>, MessageParseError> {
    lazy_static!{
        static ref RE_TOP: Regex = Regex::new(r"audit\((?P<timestamp>\d+)\.(?P<timestamp_frac>\d+):(?P<id>\d+)\):(?P<kv>\s+.+)").unwrap();
        static ref RE_KV: Regex = Regex::new("\\s+(?P<key>[^=]+)=(?P<value>[^\"]\\S*|(\"(?P<inner>[^\"]+)\"))").unwrap();
    }

    let caps = match RE_TOP.captures(message) {
        None => return Err(MessageParseError::MalformedLine(String::from(message))),
        Some(c) => c,
    };

    let timestamp_str = must_get!(caps, "timestamp");
    let timestamp = match i64::from_str_radix(timestamp_str, 10) {
        Ok(i) => i,
        Err(_) => return Err(MessageParseError::InvalidTimestamp(String::from(timestamp_str))),
    };
    let timestamp_frac_str = must_get!(caps, "timestamp_frac");
    let timestamp_frac = match i64::from_str_radix(timestamp_frac_str, 10) {
        Ok(i) => i,
        Err(_) => return Err(MessageParseError::InvalidTimestampFraction(String::from(timestamp_frac_str))),
    };
    let id_str = must_get!(caps, "id");
    let id = match i32::from_str_radix(id_str, 10) {
        Ok(i) => i,
        Err(_) => return Err(MessageParseError::InvalidId(String::from(id_str))),
    };
    let kv = must_get!(caps, "kv");

    return Ok(CommonParseResult{
        timestamp: timestamp,
        timestamp_frac: timestamp_frac,
        id: id,
        kv_iter: RE_KV.captures_iter(kv),
    });
}

// audit(1498852023.639:741): arch=c000003e syscall=59 success=yes exit=0 a0=7fffdaa8cbd0 a1=7f7af2a41cf8 a2=1b9f030 a3=598 items=2 ppid=7113 pid=7114 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts3 ses=2 comm="git" exe="/usr/bin/git" key=(null)
fn parse_syscall_record(message: &str) -> Result<SyscallRecord, MessageParseError> {
    let common = parse_common(message)?;

    let mut rec = SyscallRecord{
        id: common.id,
        timestamp: common.timestamp,
        timestamp_frac: common.timestamp_frac,
        inserted_timestamp: SystemTime::now(),
        arch: SyscallArch::Unknown,
        syscall: -1,
        success: false,
        exit: -1,
        pid: -1,
        ppid: -1,
        uid: -1,
        gid: -1,
        auid: -1,
        euid: -1,
        egid: -1,
        suid: -1,
        sgid: -1,
        fsuid: -1,
        fsgid: -1,
        tty: None,
        comm: None,
        exe: None,
        key: None,
        subj: None,
    };

    for cap in common.kv_iter {
        let key = must_get!(cap, "key");
        let value = extract_kv_value(&cap);

        // Sometimes, the value will be "(null)".  So far, I've only
        // seen this with the "key" value as in the example in the
        // comment above this function.
        if value == "(null)" {
            continue;
        }

        match key {
            "arch" => {
                rec.arch = match u32::from_str_radix(value, 16) {
                    Ok(arch) => if arch & EM_386 != 0 {
                        SyscallArch::I386
                    } else if arch & EM_X86_64 != 0 {
                        SyscallArch::Amd64
                    } else {
                        SyscallArch::Unknown
                    },
                    Err(_) => SyscallArch::Unknown,
                };
            },
            "syscall" => { rec.syscall = parse_i32_default(value, -1); },
            "success" => { rec.success = value == "yes"; },
            "exit" => { rec.exit = parse_i32_default(value, -1); },
            "pid" => { rec.pid = parse_i32_default(value, -1); },
            "ppid" => { rec.ppid = parse_i32_default(value, -1); },
            "uid" => { rec.uid = parse_i32_default(value, -1); },
            "gid" => { rec.gid = parse_i32_default(value, -1); },
            "auid" => { rec.auid = parse_i32_default(value, -1); },
            "euid" => { rec.euid = parse_i32_default(value, -1); },
            "egid" => { rec.egid = parse_i32_default(value, -1); },
            "suid" => { rec.suid = parse_i32_default(value, -1); },
            "sgid" => { rec.sgid = parse_i32_default(value, -1); },
            "fsuid" => { rec.fsuid = parse_i32_default(value, -1); },
            "fsgid" => { rec.fsgid = parse_i32_default(value, -1); },
            "tty" => { rec.tty = Some(String::from(value)); },
            "comm" => { rec.comm = Some(String::from(value)); },
            "exe" => { rec.exe = Some(String::from(value)); },
            "key" => { rec.key = Some(String::from(value)); },
            "subj" => { rec.subj = Some(String::from(value)); },
            _ => (),
        }
    }

    return Ok(rec);
}

// audit(1498852023.639:741): argc=3 a0="git" a1="rev-parse" a2="--git-dir"
fn parse_execve_record(message: &str) -> Result<ExecveRecord, MessageParseError> {
    let common = parse_common(message)?;

    let mut rec = ExecveRecord{
        id: common.id,
        timestamp: common.timestamp,
        timestamp_frac: common.timestamp_frac,
        inserted_timestamp: SystemTime::now(),
        args: Vec::new(),
    };

    let mut kv_dict: HashMap<String, String> = HashMap::new();
    for cap in common.kv_iter {
        let key = String::from(cap.name("key").unwrap().as_str());
        let value = String::from(extract_kv_value(&cap));

        kv_dict.insert(key, value);
    }

    let num_args = match kv_dict.get("argc") {
        None => return Err(MessageParseError::MalformedLine(String::from(message))),
        Some(c) => match i32::from_str_radix(c, 10) {
            Ok(i) => i,
            Err(_) => return Err(MessageParseError::InvalidArgc(c.clone())),
        },
    };

    for i in 0..num_args {
        let argname = format!("a{}", i);
        match kv_dict.remove(&argname) {
            None => (),
            Some(argval) => rec.args.push(argval),
        };
    }

    return Ok(rec);
}

#[derive(Debug)]
pub enum MessageParseError {
    UnknownType(u32),
    MalformedLine(String),
    InvalidTimestamp(String),
    InvalidTimestampFraction(String),
    InvalidId(String),
    InvalidArgc(String),
}

impl MessageParseError {
    pub fn long_description(&self) -> String {
        match self {
            &MessageParseError::UnknownType(ref message_type) => format!("Unknown message type: {}", message_type),
            &MessageParseError::MalformedLine(ref badstr) => format!("Failed to parse log line: {}", badstr),
            &MessageParseError::InvalidTimestamp(ref badstr) => format!("Timestamp value {} is not a valid base-10 number", badstr),
            &MessageParseError::InvalidTimestampFraction(ref badstr) => format!("Timestamp fraction value {} is not a valid base-10 number", badstr),
            &MessageParseError::InvalidId(ref badstr) => format!("ID value {} is not a valid base-10 number", badstr),
            &MessageParseError::InvalidArgc(ref badstr) => format!("argc value {} is not a valid base-10 number", badstr),
        }
    }
}

impl Error for MessageParseError {
    fn description(&self) -> &str {
        "Message parse error"
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl fmt::Display for MessageParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

pub fn parse_message(message_type: u32, message: &str) -> Result<AuditRecord, MessageParseError> {
    use self::AuditRecord::*;
    match message_type {
        AUDIT_SYSCALL => match parse_syscall_record(message) {
            Err(err) => Err(MessageParseError::from(err)),
            Ok(syscall_record) => Ok(Syscall(syscall_record)),
        },
        AUDIT_EXECVE => match parse_execve_record(message) {
            Err(err) => Err(MessageParseError::from(err)),
            Ok(execve_record) => Ok(Execve(execve_record)),
        },
        _ => Err(MessageParseError::UnknownType(message_type)),
    }
}

fn write_pb_and_flush<T: Message>(cos: &mut CodedOutputStream, msg: &T) -> io::Result<()> {
    match msg.write_to(cos) {
        Ok(_) => (),
        Err(pberr) => return Err(io::Error::new(io::ErrorKind::Interrupted, String::from(pberr.description()))),
    };
    match cos.flush() {
        Ok(_) => (),
        Err(pberr) => return Err(io::Error::new(io::ErrorKind::Interrupted, String::from(pberr.description()))),
    };
    return Ok(());
}

//pub fn dispatch_audit_event<T: Write>(stream: &mut T, rec1: &AuditRecord, rec2: &AuditRecord) -> io::Result<()> {
pub fn dispatch_audit_event<T: Write>(stream: &mut T, syscall: &SyscallRecord, execve: &ExecveRecord) -> io::Result<()> {
    use self::SyscallArch::*;

    // We use the timestamp from the syscall record
    // because it and the execve record should be
    // extremely close together.  In fact, they will
    // probably have the same timestamp, right down
    // to the fraction.
    let mut ts = AuditTimestamp::new();
    ts.set_timestamp(syscall.timestamp);
    ts.set_timestamp_frac(syscall.timestamp_frac);

    let mut progrec = ProgramRun::new();
    progrec.set_timestamp(ts);
    progrec.set_arch(match syscall.arch {
        Unknown => String::from("Unknown"),
        I386 => String::from("i386"),
        Amd64 => String::from("amd64"),
    });
    progrec.set_syscall(syscall.syscall);
    progrec.set_success(syscall.success);
    progrec.set_exit(syscall.exit);
    progrec.set_pid(syscall.pid);
    progrec.set_ppid(syscall.ppid);
    progrec.set_uid(syscall.uid);
    progrec.set_gid(syscall.gid);
    progrec.set_auid(syscall.auid);
    progrec.set_euid(syscall.euid);
    progrec.set_egid(syscall.egid);
    progrec.set_suid(syscall.sgid);
    progrec.set_sgid(syscall.sgid);
    progrec.set_fsuid(syscall.fsuid);
    progrec.set_fsgid(syscall.fsgid);
    // Why do I have to clone all these things?
    // Why does progrec insist on taking ownership
    // of whatever I feed to its setters?
    match syscall.tty {
        Some(ref tty) => progrec.set_tty(tty.clone()),
        _ => (),
    };
    match syscall.comm {
        Some(ref comm) => progrec.set_comm(comm.clone()),
        _ => (),
    };
    match syscall.exe {
        Some(ref exe) => progrec.set_exe(exe.clone()),
        _ => (),
    };
    match syscall.key {
        Some(ref key) => progrec.set_key(key.clone()),
        _ => (),
    };
    match syscall.subj {
        Some(ref subj) => progrec.set_tty(subj.clone()),
        _ => (),
    };
    let mut pr_args = progrec.take_args();
    for arg in &execve.args {
        // Again with the cloning!  Curse you, protobuf!
        pr_args.push(arg.clone());
    }
    progrec.set_args(pr_args);

    let mut msg = SnitchReport::new();
    msg.set_message_type(REPORT_TYPE_PROGRAMRUN);
    let mut payload = msg.take_payload();
    write_pb_and_flush(&mut CodedOutputStream::vec(&mut payload), &progrec)?;
    msg.set_payload(payload);

    let mut full_message = Vec::new();
    write_pb_and_flush(&mut CodedOutputStream::vec(&mut full_message), &msg)?;
    stream.write_u32::<NetworkEndian>(full_message.len() as u32)?;
    stream.write_all(&full_message)?;

    return Ok(());
}
