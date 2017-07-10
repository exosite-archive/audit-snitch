use std::error::Error;

use openssl::pkey::{PKey, PKeyRef};
use openssl::ec::{EcGroup, EcKey};
use openssl::x509::{X509ReqBuilder, X509Req, X509NameBuilder, X509Extension};
use openssl::stack::Stack;
use openssl::hash::MessageDigest;
use openssl::sign::Signer;

use openssl::nid;
use base64;

pub fn generate_client_key() -> Result<PKey, String> {
    let ecgroup = match EcGroup::from_curve_name(nid::SECP256K1) {
        Ok(ecg) => ecg,
        Err(_) => return Err(String::from("Unable to create SECP256K1 elliptic curve!")),
    };
    return match EcKey::generate(&ecgroup) {
        Ok(k) => match PKey::from_ec_key(k) {
            Ok(pk) => Ok(pk),
            Err(key_err) => Err(String::from(key_err.description())),
        },
        Err(key_err) => Err(String::from(key_err.description())),
    };
}

pub fn create_csr(pubkey: &PKeyRef, id: &str) -> Result<X509Req, String> {
    // HOW CAN THIS POSSIBLY FAIL?
    let mut builder = X509ReqBuilder::new().unwrap();
    // DITTO!
    builder.set_pubkey(pubkey).unwrap();
    // ...
    let mut namebuilder = X509NameBuilder::new().unwrap();
    namebuilder.append_entry_by_text("CN", id).unwrap();
    let name = namebuilder.build();
    builder.set_subject_name(&name).unwrap();

    let mut ext_stack = Stack::new().unwrap();
    {
        let ctx = builder.x509v3_context(None);
        ext_stack.push(X509Extension::new_nid(None, Some(&ctx), nid::BASIC_CONSTRAINTS, "critical,CA:FALSE").unwrap()).unwrap();
        ext_stack.push(X509Extension::new_nid(None, Some(&ctx), nid::KEY_USAGE, "critical,digitalSignature,nonRepudiation,keyEncipherment").unwrap()).unwrap();
        ext_stack.push(X509Extension::new_nid(None, Some(&ctx), nid::SUBJECT_KEY_IDENTIFIER, "hash").unwrap()).unwrap();
        ext_stack.push(X509Extension::new_nid(None, Some(&ctx), nid::EXT_KEY_USAGE, "clientAuth,emailProtection").unwrap()).unwrap();
    }
    match builder.add_extensions(&ext_stack) {
        Ok(_) => (),
        Err(openssl_err) => return Err(String::from(openssl_err.description())),
    };

    return Ok(builder.build());
}

pub fn load_hmac_key(ascii_key: &str) -> Result<PKey, String> {
    let binary_key = match base64::decode(ascii_key) {
        Ok(k) => k,
        Err(base64_err) => return Err(String::from(base64_err.description())),
    };
    match PKey::hmac(&binary_key) {
        Ok(k) => Ok(k),
        Err(openssl_err) => Err(String::from(openssl_err.description())),
    }
}

pub fn sign_data(hmac_key: &PKeyRef, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut signer = match Signer::new(MessageDigest::sha256(), hmac_key) {
        Ok(s) => s,
        Err(openssl_err) => return Err(String::from(openssl_err.description())),
    };

    match signer.update(data) {
        Ok(_) => (),
        Err(openssl_err) => return Err(String::from(openssl_err.description())),
    };

    return match signer.finish() {
        Ok(v) => Ok(v),
        Err(openssl_err) => Err(String::from(openssl_err.description())),
    };
}
