use std::iter::Iterator;
use std::collections::HashMap;
use std::ffi::CStr;
use std::time::SystemTime;
use std::ops::Drop;

use libc;

use super::{MessageParseError, AuditRecord, SyscallRecord, SyscallArch, ExecveRecord};
use super::{AUDIT_SYSCALL, AUDIT_EXECVE};

#[allow(non_camel_case_types)]
enum auparse_state_t {}

#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[repr(C)]
enum ausource_t {
    AUSOURCE_LOGS,
    AUSOURCE_FILE,
    AUSOURCE_FILE_ARRAY,
    AUSOURCE_BUFFER,
    AUSOURCE_BUFFER_ARRAY,
    AUSOURCE_DESCRIPTOR,
    AUSOURCE_FILE_POINTER,
    AUSOURCE_FEED,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct au_event_t {
    sec: libc::time_t,
    milli: libc::c_uint,
    serial: libc::c_ulong,
    host: *const libc::c_char,
}

#[link(name = "auparse")]
extern {
    fn auparse_init(source: ausource_t, b: *const libc::c_void) -> *mut auparse_state_t;
    fn auparse_destroy(au: *mut auparse_state_t);
    fn auparse_next_event(au: *mut auparse_state_t) -> libc::c_int;
    fn auparse_next_record(au: *mut auparse_state_t) -> libc::c_int;
    fn auparse_get_type(au: *mut auparse_state_t) -> libc::c_int;
    fn auparse_get_timestamp(au: *mut auparse_state_t) -> *const au_event_t;
    fn auparse_first_field(au: *mut auparse_state_t) -> libc::c_int;
    fn auparse_next_field(au: *mut auparse_state_t) -> libc::c_int;
    fn auparse_get_field_name(au: *mut auparse_state_t) -> *const libc::c_char;
    fn auparse_get_field_str(au: *mut auparse_state_t) -> *const libc::c_char;
}

pub struct AuRecord {
    pub rec_type: u32,
    pub timestamp: i64,
    pub timestamp_frac: i64,
    pub serial: u64,
    pub fields: HashMap<String, String>,
}

pub struct AuParser {
    state: *mut auparse_state_t,
    first_read: bool,
    error: i32,
}

impl AuParser {
    pub fn new_stdin() -> Self {
        unsafe { Self::new_fd(0) }
    }

    pub unsafe fn new_fd(fd: libc::c_int) -> Self {
        AuParser{
            state: auparse_init(ausource_t::AUSOURCE_DESCRIPTOR, fd as *const libc::c_void),
            first_read: true,
            error: 0,
        }
    }

}

unsafe fn c_str_to_string(c_str: *const libc::c_char) -> String {
    let cs = CStr::from_ptr(c_str);
    match cs.to_str() {
        Ok(valid_str) => valid_str.to_owned(),
        Err(_) => String::from(""),
    }
}

impl Drop for AuParser {
    fn drop(&mut self) {
        unsafe { auparse_destroy(self.state) };
    }
}
                                          
impl Iterator for AuParser {
    type Item = AuRecord;

    fn next(&mut self) -> Option<AuRecord> {
        unsafe {
            let rec_result = if self.first_read {
                self.first_read = false;
                auparse_next_event(self.state)
            } else {
                let rec_result = auparse_next_record(self.state);
                if rec_result < 0 {
                    self.error = rec_result;
                    return None;
                }
                rec_result
            };
            println!("rec_result = {}", rec_result);
            if rec_result == 0 {
                let evt_result = auparse_next_event(self.state);
                if evt_result < 0 {
                    self.error = evt_result;
                    return None;
                }
                if evt_result == 0 {
                    return None;
                }
            }

            let ts = auparse_get_timestamp(self.state);
            if ts.is_null() {
                self.error = -1;
                return None;
            }

            let rec_type = auparse_get_type(self.state);
            let timestamp = (*ts).sec as i64;
            let timestamp_frac = (*ts).milli as i64;
            let serial = (*ts).serial;
            let mut fields = HashMap::new();

            let mut field_result = auparse_first_field(self.state);
            if field_result < 0 {
                self.error = field_result;
                return None;
            }
            if field_result == 0 {
                return None;
            }

            loop {
                let c_name = auparse_get_field_name(self.state);
                let c_value = auparse_get_field_str(self.state);
                
                let name = c_str_to_string(c_name);
                let value = c_str_to_string(c_value);

                if name != "" {
                    fields.insert(name, value);
                }

                field_result = auparse_next_field(self.state);
                if field_result <= 0 {
                    break
                }
            }

            return Some(AuRecord{
                rec_type: rec_type as u32,
                timestamp: timestamp,
                timestamp_frac: timestamp_frac,
                serial: serial,
                fields: fields,
            });
        }
    }
}

impl super::Parser for AuParser {
    fn read_event(&mut self) -> Result<AuditRecord, MessageParseError> {
        use super::AuditRecord::*;

        loop {
            match self.next() {
                None => return Err(MessageParseError::Eof),
                Some(aurec) => {
                    match parse_syscall_record(&aurec) {
                        Some(syscall_rec) => return Ok(Syscall(syscall_rec)),
                        None => match parse_execve_record(&aurec) {
                            Err(_) => (),
                            Ok(None) => (),
                            Ok(Some(execve_rec)) => return Ok(Execve(execve_rec)),
                        }
                    }
                }
            };
        }
    }
}

fn parse_syscall_record(aurec: &AuRecord) -> Option<SyscallRecord> {
    if aurec.rec_type != AUDIT_SYSCALL {
        return None;
    }
    let mut rec = SyscallRecord{
        id: aurec.serial,
        timestamp: aurec.timestamp,
        timestamp_frac: aurec.timestamp_frac,
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

    for (key, v) in &aurec.fields {
        let value = remove_quotes(v);
        super::syscall_extract_fields(&mut rec, &key, &value);
    }

    return Some(rec);
}

fn remove_quotes(arg: &str) -> String {
    if arg.starts_with('"') {
        String::from(&arg[1..arg.len()-1])
    } else {
        String::from(arg)
    }
}

fn cleanup_proc_arg(arg: &str) -> String {
    if arg.starts_with('"') {
        String::from(&arg[1..arg.len()-1])
    } else {
        let mut bytes = Vec::new();
        for i in 0..(arg.len()/2) {
            match u8::from_str_radix(&arg[2*i..2*i+2], 16) {
                Ok(b) => bytes.push(b),
                Err(_) => return String::from(arg),
            }
        }
        match String::from_utf8(bytes) {
            Ok(s) => format!("\"{}\"", s),
            Err(_) => String::from(arg)
        }
    }
}

fn parse_execve_record(aurec: &AuRecord) -> Result<Option<ExecveRecord>, MessageParseError> {
    if aurec.rec_type != AUDIT_EXECVE {
        return Ok(None);
    }
    let mut rec = ExecveRecord{
        id: aurec.serial,
        timestamp: aurec.timestamp,
        timestamp_frac: aurec.timestamp_frac,
        inserted_timestamp: SystemTime::now(),
        args: Vec::new(),
    };

    let num_args = match aurec.fields.get("argc") {
        None => return Err(MessageParseError::MalformedLine(String::from("LIBAUPARSE IN USE.  SORRY."))),
        Some(c) => match i32::from_str_radix(c, 10) {
            Ok(i) => i,
            Err(_) => return Err(MessageParseError::InvalidArgc(c.clone())),
        },
    };

    for i in 0..num_args {
        let argname = format!("a{}", i);
        match aurec.fields.get(&argname) {
            None => (),
            Some(argval) => rec.args.push(cleanup_proc_arg(&argval)),
        };
    }

    return Ok(Some(rec));
}
