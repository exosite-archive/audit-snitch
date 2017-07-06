use std::{io, mem, ptr, thread, time, i64, i32};

use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use std::error::Error;

use regex::{Regex, Captures};
use protobuf::{CodedOutputStream, Message};
use self::protos::{AuditTimestamp, ProgramRun, SnitchReport};

use libc;

mod protos;

// From linux/audit.h
pub const AUDIT_SYSCALL: u32 = 1300;
pub const AUDIT_EXECVE: u32 = 1309;
pub const AUDIT_ARCH_64BIT: u32 = 0x80000000;
pub const AUDIT_ARCH_LE: u32 = 0x40000000;

// From linux/elf-em.h
pub const EM_386: u32 = 3;
pub const EM_X86_64: u32 = 62;

// From audit.proto
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
    unsafe {
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
            //let hdr: audit_dispatcher_header = mem::transmute(bytes.as_slice());
            //println!("{}", bytes.len());
            //println!("{:?}", bytes);
            let hdr: audit_dispatcher_header = ptr::read(bytes.as_ptr() as *const _);
            return Ok(audit_dispatcher_header{
                ver: hdr.ver,
                hlen: hdr.hlen,
                msg_type: hdr.msg_type,
                size: hdr.size,
            });
        }
    }
}

pub fn read_message<T: Read>(f: &mut T, expected_size: usize) -> io::Result<String> {
    unsafe {
        let mut msg_bytes = Vec::with_capacity(expected_size);
        let mut chunk = f.take(expected_size as u64);
        let bytes_read = chunk.read_to_end(&mut msg_bytes)?;
        if bytes_read < expected_size {
            panic!("Not enough message bytes read!");
        }
        let msg = String::from_raw_parts(msg_bytes.as_mut_ptr(), expected_size, expected_size);
        return Ok(msg.clone());
    }
}

pub enum SyscallArch {
    Unknown,
    I386,
    Amd64,
}

pub struct SyscallRecord {
    id: i32,
    timestamp: i64,
    timestamp_frac: i64,
    inserted_timestamp: u64,
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

pub struct ExecveRecord {
    id: i32,
    timestamp: i64,
    timestamp_frac: i64,
    inserted_timestamp: u64,
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

// audit(1498852023.639:741): arch=c000003e syscall=59 success=yes exit=0 a0=7fffdaa8cbd0 a1=7f7af2a41cf8 a2=1b9f030 a3=598 items=2 ppid=7113 pid=7114 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts3 ses=2 comm="git" exe="/usr/bin/git" key=(null)
fn parse_syscall_record(message: &str) -> Option<SyscallRecord> {
    lazy_static!{
        // These should be the same as below.
        static ref RE_TOP: Regex = Regex::new(r"audit\((?P<timestamp>\d+)\.(?P<timestamp_frac>\d+)\):(?P<id>\d+)(?P<kv>\s+.+)").unwrap();
        static ref RE_KV: Regex = Regex::new("\\s+(?P<key>[^=]+)=(?P<value>\\S+|(\"(?P<inner>[^\"]+)\"))").unwrap();
    }

    // TODO: properly report all parsing failures
    let caps = match RE_TOP.captures(message) {
        None => return None,
        Some(c) => c,
    };

    let timestamp = match i64::from_str_radix(caps.name("timestamp").unwrap().as_str(), 10) {
        Ok(i) => i,
        Err(_) => return None,
    };
    let timestamp_frac = match i64::from_str_radix(caps.name("timestamp_frac").unwrap().as_str(), 10) {
        Ok(i) => i,
        Err(_) => return None,
    };
    let id = match i32::from_str_radix(caps.name("id").unwrap().as_str(), 10) {
        Ok(i) => i,
        Err(_) => return None,
    };
    let kv = caps.name("kv").unwrap().as_str();

    let ts_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut rec = SyscallRecord{
        id: id,
        timestamp: timestamp,
        timestamp_frac: timestamp_frac,
        inserted_timestamp: ts_now,
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

    for cap in RE_KV.captures_iter(kv) {
        let key = cap.name("key").unwrap().as_str();
        let value = extract_kv_value(&cap);

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

    return Some(rec);
}

// audit(1498852023.639:741): argc=3 a0="git" a1="rev-parse" a2="--git-dir"
fn parse_execve_record(message: &str) -> Option<ExecveRecord> {
    lazy_static!{
        // These should be the same as below.
        static ref RE_TOP: Regex = Regex::new(r"audit\((?P<timestamp>\d+)\.(?P<timestamp_frac>\d+)\):(?P<id>\d+)(?P<kv>\s+.+)").unwrap();
        static ref RE_KV: Regex = Regex::new("\\s+(?P<key>[^=]+)=(?P<value>\\S+|(\"(?P<inner>[^\"]+)\"))").unwrap();
    }

    // TODO: properly report all parsing failures
    let caps = match RE_TOP.captures(message) {
        None => return None,
        Some(c) => c,
    };

    let timestamp = match i64::from_str_radix(caps.name("timestamp").unwrap().as_str(), 10) {
        Ok(i) => i,
        Err(_) => return None,
    };
    let timestamp_frac = match i64::from_str_radix(caps.name("timestamp_frac").unwrap().as_str(), 10) {
        Ok(i) => i,
        Err(_) => return None,
    };
    let id = match i32::from_str_radix(caps.name("id").unwrap().as_str(), 10) {
        Ok(i) => i,
        Err(_) => return None,
    };
    let kv = caps.name("kv").unwrap().as_str();

    let ts_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut rec = ExecveRecord{
        id: id,
        timestamp: timestamp,
        timestamp_frac: timestamp_frac,
        inserted_timestamp: ts_now,
        args: Vec::new(),
    };

    let mut kv_dict: HashMap<String, String> = HashMap::new();
    for cap in RE_KV.captures_iter(kv) {
        let key = String::from(cap.name("key").unwrap().as_str());
        let value = String::from(extract_kv_value(&cap));

        kv_dict.insert(key, value);
    }

    let num_args = match kv_dict.get("argc") {
        None => return None,
        Some(c) => match i32::from_str_radix(c, 10) {
            Ok(i) => i,
            Err(_) => return None,
        },
    };

    for i in 0..num_args {
        let argname = format!("a{}", i);
        match kv_dict.remove(&argname) {
            None => (),
            Some(argval) => rec.args.push(argval),
        };
    }

    return Some(rec);
}

pub fn parse_message(message_type: u32, message: &str) -> Option<AuditRecord> {
    use self::AuditRecord::*;
    match message_type {
        AUDIT_SYSCALL => match parse_syscall_record(message) {
            None => None,
            Some(syscall_record) => Some(Syscall(syscall_record)),
        },
        AUDIT_EXECVE => match parse_execve_record(message) {
            None => None,
            Some(execve_record) => Some(Execve(execve_record)),
        },
        _ => None,
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

pub fn dispatch_audit_event<T: Write>(stream: &mut T, rec1: &AuditRecord, rec2: &AuditRecord) -> io::Result<()> {
    use self::AuditRecord::*;
    use self::SyscallArch::*;
    let syscall = match rec1 {
        &Syscall(ref syscall) => syscall,
        &Execve(_) => match rec2 {
            &Syscall(ref syscall) => syscall,
            &Execve(_) => return Err(io::Error::new(io::ErrorKind::Other, "No syscall record found!")),
        },
    };
    let execve = match rec1 {
        &Execve(ref execve) => execve,
        &Syscall(_) => match rec2 {
            &Execve(ref execve) => execve,
            &Syscall(_) => return Err(io::Error::new(io::ErrorKind::Other, "No execve record found!")),
        },
    };

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

    let mut cos = CodedOutputStream::new(stream);
    write_pb_and_flush(&mut cos, &msg)?;

    return Ok(());
}
