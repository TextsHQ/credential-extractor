fn main() {
    #[cfg(target_os = "windows")]
    windows::build!(
        Windows::Win32::Security::CryptUnprotectData,
        Windows::Win32::Security::Cryptography::Core::CRYPTOAPI_BLOB,
    );
}
