extern crate protoc_rust;
extern crate openssl;

const OPENSSL_MASK_MAJOR: i64 = 0xf0000000;
const OPENSSL_MASK_MINOR: i64 = 0x0ff00000;
const OPENSSL_MASK_FIX: i64 =   0x000ff000;
// These shifts are expressed in nibbles, hence the * 4.
const OPENSSL_SHIFT_MAJOR: i64 = 7 * 4;
const OPENSSL_SHIFT_MINOR: i64 = 5 * 4;
const OPENSSL_SHIFT_FIX: i64 = 3 * 4;

fn main() {
    protoc_rust::run(protoc_rust::Args {
        out_dir: "src/audit/protos",
        input: &["protos/audit.proto"],
        includes: &["protos"],
    }).expect("protoc");

    let openssl_version = openssl::version::number();
    let openssl_major = (openssl_version & OPENSSL_MASK_MAJOR) >> OPENSSL_SHIFT_MAJOR;
    let openssl_minor = (openssl_version & OPENSSL_MASK_MINOR) >> OPENSSL_SHIFT_MINOR;
    let openssl_fix = (openssl_version & OPENSSL_MASK_FIX) >> OPENSSL_SHIFT_FIX;
    match (openssl_major, openssl_minor, openssl_fix) {
        (1, 0, 1) => {
            println!("cargo:rustc-cfg=openssl101");
        }
        (1, 0, 2) => {
            println!("cargo:rustc-cfg=openssl102");
        }
        (1, 1, 0) => {
            println!("cargo:rustc-cfg=openssl110");
        }
        _ => panic!("Wrong rust-openssl version: 0x{:x} ({}.{}.{})", openssl_version, openssl_major, openssl_minor, openssl_fix),
    }
}
