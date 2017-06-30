extern crate regex;
extern crate libc;
extern crate protobuf;
extern crate chan_signal;

use std::{io, mem, ptr, thread, time};

use std::fs::File;
use chan_signal::Signal;
use std::io::{Read, Write};

#[repr(C)]
struct audit_dispatcher_header {
    ver: libc::uint32_t,
    hlen: libc::uint32_t,
    msg_type: libc::uint32_t,
    size: libc::uint32_t,
}

fn read_header<T: Read>(f: &mut T) -> io::Result<audit_dispatcher_header> {
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

fn read_message<T: Read>(f: &mut T, expected_size: usize) -> io::Result<String> {
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

    let mut outfile = match File::create("/tmp/foobar.log") {
        Ok(f) => f,
        Err(_) => panic!("Failed to open /tmp/foobar.log!"),
    };
    while should_run {
        let hdr = match read_header(&mut stdin) {
            Ok(hdr_struct) => hdr_struct,
            Err(_) => {
                should_run = false;
                break;
            },
        };
        if hdr.ver != 0 {
            panic!("Unsupported audit version: {}", hdr.ver);
        }
        //println!("Message size: {}", hdr.size);
        let msg = match read_message(&mut stdin, hdr.size as usize) {
            Ok(msg_str) => msg_str,
            Err(_) => panic!("Failed to read message!"),
        };
        write!(outfile, "{}\n", msg).unwrap();
        //println!("{}", msg);
    }
}
