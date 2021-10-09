pub const KNOWN_BROWSER: &[FirefoxBrowser] = &[FirefoxBrowser {
    name: "Firefox",
    paths: &["Mozilla", "Firefox", "Profiles"],
}];

pub struct FirefoxBrowser {
    pub name: &'static str,

    pub paths: &'static [&'static str],
}
