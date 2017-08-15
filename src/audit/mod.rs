use std::{io, i64, i32, fmt, str};

use std::io::Write;
use std::time::SystemTime;
use std::error::Error;

use protobuf::{CodedOutputStream, Message};
use byteorder::{NetworkEndian, WriteBytesExt};
use self::protos::{AuditTimestamp, ProgramRun, SnitchReport};

mod protos;
mod aubin;

pub use self::aubin::BinParser;

// From audit.proto
#[allow(dead_code)]
pub const REPORT_TYPE_ERROR: i32 = 0;
pub const REPORT_TYPE_PROGRAMRUN: i32 = 1;

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


#[derive(Debug)]
pub enum MessageParseError {
    UnknownType(u32),
    MalformedLine(String),
    InvalidTimestamp(String),
    InvalidTimestampFraction(String),
    InvalidId(String),
    InvalidArgc(String),
    InvalidVersion(u32),
    IoError(io::Error),
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
            &MessageParseError::InvalidVersion(ref badver) => format!("Unsupported audit version: {}", badver),
            &MessageParseError::IoError(ref ioerr) => ioerr.description().to_owned(),
        }
    }
}

impl Error for MessageParseError {
    fn description(&self) -> &str {
        match self {
            &MessageParseError::IoError(ref ioerr) => ioerr.description(),
            _ => "Message parse error",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match self {
            &MessageParseError::IoError(ref ioerr) => Some(ioerr),
            _ => None,
        }
    }
}

impl fmt::Display for MessageParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
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

pub trait Parser {
    fn read_event(&mut self) -> Result<AuditRecord, MessageParseError>;
}
