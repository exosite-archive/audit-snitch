use std::{io, mem, thread, time, i64, i32};

use std::io::Read;
use std::time::SystemTime;
use std::collections::HashMap;
use std::error::Error;
use std::slice;
use std::str;

use super::{MessageParseError, AuditRecord, SyscallRecord, SyscallArch, ExecveRecord};

use regex::{Regex, Captures, CaptureMatches};

use libc;

#[repr(C)]
pub struct audit_dispatcher_header {
    pub ver: libc::uint32_t,
    pub hlen: libc::uint32_t,
    pub msg_type: libc::uint32_t,
    pub size: libc::uint32_t,
}

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

pub fn parse_message(message_type: u32, message: &str) -> Result<super::AuditRecord, MessageParseError> {
    use super::AuditRecord::*;
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

pub struct BinParser<'a, T: Read>  where T: 'a {
    f: &'a mut T,
}

impl<'a, T: Read> BinParser<'a, T> {
    pub fn new(f: &'a mut T) -> BinParser<T> {
        BinParser{
            f: f,
        }
    }
}

impl<'a, T: Read> super::Parser for BinParser<'a, T> {
    fn read_event(&mut self) -> Result<AuditRecord, MessageParseError> {
        let hdr = match read_header(self.f) {
            Ok(hdr_struct) => hdr_struct,
            Err(ioerr) => {
                return Err(MessageParseError::IoError(ioerr));
            },
        };
        if hdr.ver != 0 {
            return Err(MessageParseError::InvalidVersion(hdr.ver));
        }
        let msg = match read_message(self.f, hdr.size as usize) {
            Ok(msg_str) => msg_str,
            Err(ioerr) => {
                return Err(MessageParseError::IoError(ioerr));
            },
        };
        return parse_message(hdr.msg_type, &msg);
    }
}
