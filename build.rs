fn main() {
    windows::build!(
        Windows::Win32::Security::CryptUnprotectData,
    );
}
