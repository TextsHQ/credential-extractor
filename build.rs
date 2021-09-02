fn main() {
    windows::build!(
        Windows::Win32::Security::CryptUnprotectData,
        Windows::Win32::Security::Cryptography::Core::CRYPTOAPI_BLOB,
    );
}
