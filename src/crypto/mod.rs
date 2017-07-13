use std::error::Error;
use std::fmt;
use std::convert;

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

pub fn generate_client_key(key_type: KeyType) -> Result<PKey, ErrorStack> {
    use self::KeyType::*;

    match key_type {
        Ecdsa(curve_type) => {
            let ecgroup = curve_type.to_ecgroup()?;
            PKey::from_ec_key(EcKey::generate(&ecgroup)?)
        },
        Rsa(key_size) => PKey::from_rsa(rsa::Rsa::generate(key_size)?),
    }
}

pub fn create_csr(privkey: &PKeyRef, pubkey: &PKeyRef, id: &str) -> Result<X509Req, ErrorStack> {
    // HOW CAN THIS POSSIBLY FAIL?
    let mut builder = X509ReqBuilder::new()?;
    // DITTO!
    builder.set_pubkey(pubkey)?;
    // ...
    let mut namebuilder = X509NameBuilder::new()?;
    namebuilder.append_entry_by_text("CN", id)?;
    let name = namebuilder.build();
    builder.set_subject_name(&name)?;
    builder.set_version(0)?;

    let mut ext_stack = Stack::new()?;
    {
        let ctx = builder.x509v3_context(None);
        ext_stack.push(X509Extension::new_nid(None, Some(&ctx), nid::BASIC_CONSTRAINTS, "critical,CA:FALSE")?)?;
        ext_stack.push(X509Extension::new_nid(None, Some(&ctx), nid::KEY_USAGE, "critical,digitalSignature,nonRepudiation,keyEncipherment")?)?;
        ext_stack.push(X509Extension::new_nid(None, Some(&ctx), nid::SUBJECT_KEY_IDENTIFIER, "hash")?)?;
        ext_stack.push(X509Extension::new_nid(None, Some(&ctx), nid::EXT_KEY_USAGE, "clientAuth,emailProtection")?)?;
    }
    builder.add_extensions(&ext_stack)?;
    builder.sign(privkey, MessageDigest::sha256())?;

    return Ok(builder.build());
}

#[derive(Debug)]
pub enum HmacLoadError {
    OpenSSL(ErrorStack),
    Base64(base64::DecodeError),
}

impl Error for HmacLoadError {
    fn description(&self) -> &str {
        match self {
            &HmacLoadError::OpenSSL(ref err) => err.description(),
            &HmacLoadError::Base64(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        match self {
            &HmacLoadError::OpenSSL(ref err) => Some(err),
            &HmacLoadError::Base64(ref err) => Some(err),
        }
    }
}

impl fmt::Display for HmacLoadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl convert::From<ErrorStack> for HmacLoadError {
    fn from(err: ErrorStack) -> Self {
        HmacLoadError::OpenSSL(err)
    }
}

impl convert::From<base64::DecodeError> for HmacLoadError {
    fn from(err: base64::DecodeError) -> Self {
        HmacLoadError::Base64(err)
    }
}

pub fn load_hmac_key(ascii_key: &str) -> Result<PKey, HmacLoadError> {
    let binary_key = base64::decode(ascii_key)?;
    Ok(PKey::hmac(&binary_key)?)
}

pub fn sign_data(hmac_key: &PKeyRef, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut signer = Signer::new(MessageDigest::sha256(), hmac_key)?;
    signer.update(data)?;
    return signer.finish()
}
