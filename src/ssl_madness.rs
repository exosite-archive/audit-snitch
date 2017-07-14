use std::path::Path;
use std::convert::AsRef;

use openssl::{ssl, x509};
use openssl::error::ErrorStack;

// The following functions were inferred from rust-openssl source code.
// ALL I WANTED TO DO WAS USE A CLIENT CERTIFICATE!  ARGH!

#[cfg(openssl101)]
fn setup_curves(ctx: &mut ssl::SslContextBuilder) -> Result<(), ErrorStack> {
    use openssl::ec::EcKey;
    use openssl::nid;

    let curve = try!(EcKey::from_curve_name(nid::X9_62_PRIME256V1));
    ctx.set_tmp_ecdh(&curve)
}

#[cfg(openssl102)]
fn setup_curves(ctx: &mut ssl::SslContextBuilder) -> Result<(), ErrorStack> {
    ctx.set_ecdh_auto(true)
}

#[cfg(openssl110)]
fn setup_curves(_: &mut ssl::SslContextBuilder) -> Result<(), ErrorStack> {
    Ok(())
}

fn create_ssl_context_common() -> Result<ssl::SslContextBuilder, ErrorStack> {
    let mut ctx = try!(ssl::SslContextBuilder::new(ssl::SslMethod::tls()));

    let mut opts = ssl::SSL_OP_ALL;
    opts &= !ssl::SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
    opts &= !ssl::SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
    opts |= ssl::SSL_OP_NO_TICKET;
    opts |= ssl::SSL_OP_NO_COMPRESSION;
    opts |= ssl::SSL_OP_NO_SSLV2;
    opts |= ssl::SSL_OP_NO_SSLV3;
    opts |= ssl::SSL_OP_NO_TLSV1;
    opts |= ssl::SSL_OP_NO_TLSV1_1;
    opts |= ssl::SSL_OP_SINGLE_DH_USE;
    opts |= ssl::SSL_OP_SINGLE_ECDH_USE;
    opts |= ssl::SSL_OP_CIPHER_SERVER_PREFERENCE;
    ctx.set_options(opts);

    let mode = ssl::SSL_MODE_AUTO_RETRY | ssl::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
               ssl::SSL_MODE_ENABLE_PARTIAL_WRITE;
    ctx.set_mode(mode);

    try!(setup_curves(&mut ctx));
    try!(ctx.set_cipher_list("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                              ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
                              ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                              ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:\
                              ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"));

    return Ok(ctx);
}

#[allow(dead_code)]
pub fn create_ssl_context() -> Result<ssl::SslContext, ErrorStack> {
    let builder = create_ssl_context_common()?;
    return Ok(builder.build());
}

pub fn create_ssl_context_with_client_cert<P: AsRef<Path>>(client_cert_and_chain_file: P, client_private_key_file: P) -> Result<ssl::SslContext, ErrorStack> {
    let mut builder = create_ssl_context_common()?;

    try!(builder.set_certificate_chain_file(client_cert_and_chain_file));
    try!(builder.set_private_key_file(client_private_key_file, x509::X509_FILETYPE_PEM));

    return Ok(builder.build());
}
