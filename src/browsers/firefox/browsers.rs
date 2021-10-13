pub const KNOWN_BROWSER: &[FirefoxBrowser] = &[FirefoxBrowser {
    name: "Firefox",
    paths: &["Mozilla", "Firefox", "Profiles"],
    macos_paths: &["Firefox", "Profiles"],
    linux_paths: &[".mozilla", "firefox"],
}];

pub struct FirefoxBrowser {
    pub name: &'static str,

    pub paths: &'static [&'static str],
    pub macos_paths: &'static [&'static str],
    pub linux_paths: &'static [&'static str],
}
