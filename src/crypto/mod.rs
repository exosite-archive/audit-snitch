use std::error::Error;
use std::fmt;

use openssl::pkey::{PKey, PKeyRef};
use openssl::ec::{EcGroup, EcKey, NAMED_CURVE};
use openssl::x509::{X509ReqBuilder, X509Req, X509NameBuilder, X509Extension};
use openssl::stack::Stack;
use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use openssl::error::ErrorStack;

use openssl::{nid, rsa};
use base64;

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum ECurve {
    Secp256k1,
    Secp384r1,
    Prime256v1,
}

impl ECurve {
    fn to_ecgroup(self) -> Result<EcGroup, ErrorStack> {
        let mut ecgroup = EcGroup::from_curve_name(match self {
            ECurve::Secp256k1 => nid::SECP256K1,
            ECurve::Secp384r1 => nid::SECP384R1,
            ECurve::Prime256v1 => nid::X9_62_PRIME256V1,
        })?;
        ecgroup.set_asn1_flag(NAMED_CURVE);
        return Ok(ecgroup);
    }
}

impl fmt::Display for ECurve {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &ECurve::Secp256k1 => write!(f, "secp256k1"),
            &ECurve::Secp384r1 => write!(f, "secp384r1"),
            &ECurve::Prime256v1 => write!(f, "prime256v1"),
        }
    }
}

#[allow(dead_code)]
pub enum KeyType {
    Ecdsa(ECurve),
    Rsa(u32),
}

pub fn generate_client_key(key_type: KeyType) -> Result<PKey, String> {
    use self::KeyType::*;

    match key_type {
        Ecdsa(curve_type) => {
            let ecgroup = match curve_type.to_ecgroup() {
                Ok(ecg) => ecg,
                Err(_) => return Err(format!("Unable to create {} elliptic curve!", curve_type)),
            };
            match EcKey::generate(&ecgroup) {
                Ok(k) => match PKey::from_ec_key(k) {
                    Ok(pk) => Ok(pk),
                    Err(key_err) => Err(String::from(key_err.description())),
                },
                Err(key_err) => Err(String::from(key_err.description())),
            }
        },
        Rsa(key_size) => match rsa::Rsa::generate(key_size) {
            Ok(k) => match PKey::from_rsa(k) {
                Ok(pk) => Ok(pk),
                Err(key_err) => Err(String::from(key_err.description())),
            },
            Err(key_err) => Err(String::from(key_err.description())),
        },
    }
}

pub fn create_csr(privkey: &PKeyRef, pubkey: &PKeyRef, id: &str) -> Result<X509Req, String> {
    // HOW CAN THIS POSSIBLY FAIL?
    let mut builder = X509ReqBuilder::new().unwrap();
    // DITTO!
    builder.set_pubkey(pubkey).unwrap();
    // ...
    let mut namebuilder = X509NameBuilder::new().unwrap();
    namebuilder.append_entry_by_text("CN", id).unwrap();
    let name = namebuilder.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_version(0).unwrap();

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
    match builder.sign(privkey, MessageDigest::sha256()) {
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
