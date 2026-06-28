//! RFC 8879 certificate decompressors advertised by Firefox 152: zlib, brotli, zstd.
//! The client never compresses its own (absent) certificate, so `ENABLE_ENCODING`
//! stays false and only `decode` is implemented. Servers (e.g. Cloudflare) send a
//! compressed Certificate that NSS decompresses through these. NSS pre-sizes the
//! output buffer to the advertised uncompressed length, so `decode` must fill it
//! exactly (a length mismatch is an error).
use std::io::Read;

use crate::{
    agent::CertificateCompressor,
    err::{Error, Res},
};

fn finish(decoded: &[u8], output: &mut [u8]) -> Res<()> {
    if decoded.len() != output.len() {
        return Err(Error::CertificateDecoding);
    }
    output.copy_from_slice(decoded);
    Ok(())
}

/// RFC 8879 algorithm 1: zlib (RFC 1950).
pub struct Zlib;
impl CertificateCompressor for Zlib {
    const ID: u16 = 1;
    const NAME: &std::ffi::CStr = c"zlib";
    fn decode(input: &[u8], output: &mut [u8]) -> Res<()> {
        let mut v = Vec::with_capacity(output.len());
        flate2::read::ZlibDecoder::new(input)
            .read_to_end(&mut v)
            .map_err(|_| Error::CertificateDecoding)?;
        finish(&v, output)
    }
}

/// RFC 8879 algorithm 2: brotli.
pub struct Brotli;
impl CertificateCompressor for Brotli {
    const ID: u16 = 2;
    const NAME: &std::ffi::CStr = c"brotli";
    fn decode(input: &[u8], output: &mut [u8]) -> Res<()> {
        let mut v = Vec::with_capacity(output.len());
        brotli_decompressor::Decompressor::new(input, 4096)
            .read_to_end(&mut v)
            .map_err(|_| Error::CertificateDecoding)?;
        finish(&v, output)
    }
}

/// RFC 8879 algorithm 3: zstd.
pub struct Zstd;
impl CertificateCompressor for Zstd {
    const ID: u16 = 3;
    const NAME: &std::ffi::CStr = c"zstd";
    fn decode(input: &[u8], output: &mut [u8]) -> Res<()> {
        let v = zstd::stream::decode_all(input).map_err(|_| Error::CertificateDecoding)?;
        finish(&v, output)
    }
}
