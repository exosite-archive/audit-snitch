extern crate regex;
extern crate libc;
extern crate protobuf;
extern crate chan_signal;

use std::io;
use std::mem;
use std::thread;

use std::fs::File;
use chan_signal::Signal;
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};

#[repr(C)]
struct audit_dispatcher_header {
    ver: libc::uint32_t,
    hlen: libc::uint32_t,
    msg_type: libc::uint32_t,
    size: libc::uint32_t,
}

fn open_stdin() -> File {
    unsafe {
        return File::from_raw_fd(0 as RawFd);
    }
}

fn read_header(f: &mut File) -> io::Result<audit_dispatcher_header> {
    unsafe {
        let mut bytes = Vec::with_capacity(mem::size_of::<audit_dispatcher_header>());
        let bytes_read = f.read(&mut bytes)?;
        if bytes_read < mem::size_of::<audit_dispatcher_header>() {
            panic!("Not enough header bytes read!");
        }
        let hdr: audit_dispatcher_header = mem::transmute(bytes.as_slice());
        return Ok(audit_dispatcher_header{
            ver: hdr.ver,
            hlen: hdr.hlen,
            msg_type: hdr.msg_type,
            size: hdr.size,
        });
    }
}

fn read_message(f: &mut File, expected_size: usize) -> io::Result<String> {
    unsafe {
        let mut msg_bytes = Vec::with_capacity(expected_size);
        let bytes_read = f.read(&mut msg_bytes)?;
        if bytes_read < expected_size {
            panic!("Not enough message bytes read!");
        }
        let msg = String::from_raw_parts(msg_bytes.as_mut_ptr(), expected_size, expected_size);
        return Ok(msg.clone());
    }
}

fn main() {
    let mut stdin = open_stdin();
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

    let mut outfile = match File::create("/tmp/foobar.log") {
        Ok(f) => f,
        Err(_) => panic!("Failed to open /tmp/foobar.log!"),
    };
    while should_run {
        let hdr = match read_header(&mut stdin) {
            Ok(hdr_struct) => hdr_struct,
            Err(_) => panic!("Failed to read header!"),
        };
        let msg = match read_message(&mut stdin, hdr.size as usize) {
            Ok(msg_str) => msg_str,
            Err(_) => panic!("Failed to read message!"),
        };
        write!(outfile, "{}\n", msg).unwrap();
    }
}
