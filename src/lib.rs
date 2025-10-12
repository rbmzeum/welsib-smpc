pub mod server;
pub mod client;
pub mod verifier;
pub mod conv;
pub mod helpers;
pub mod http;
pub mod smpc;
pub mod checksum;
pub mod base64;
pub mod certificate;
pub mod random;
pub mod hash;
pub mod d;

pub use crate::d::d;

pub unsafe fn struct_to_bytes<T>(s: &T) -> &[u8] {
    std::slice::from_raw_parts(
        (s as *const T) as *const u8,
        std::mem::size_of::<T>()
    )
}