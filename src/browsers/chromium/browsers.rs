pub const KNOWN_BROWSER: &[ChromiumBrowser] = &[
    ChromiumBrowser {
        name: "Chrome",

        paths: &["Google", "Chrome"],

        macos_service: "Chrome Safe Storage",
        macos_account: "Chrome",
    },
    ChromiumBrowser {
        name: "Edge",

        paths: &["Microsoft", "Edge"],

        macos_service: "",
        macos_account: "",
    },
    ChromiumBrowser {
        name: "Brave",

        paths: &["BraveSoftware", "Brave-Browser"],

        macos_service: "Brave Safe Storage",
        macos_account: "Brave",
    },
    ChromiumBrowser {
        name: "Vivaldi",

        paths: &["Vivaldi"],

        macos_service: "Vivaldi Safe Storage",
        macos_account: "Vivaldi",
    },
];

pub struct ChromiumBrowser {
    pub name: &'static str,

    pub paths: &'static [&'static str],

    pub macos_service: &'static str,
    pub macos_account: &'static str,
}
