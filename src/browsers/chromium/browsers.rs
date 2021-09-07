pub const KNOWN_BROWSER: &[ChromiumBrowser] = &[
    ChromiumBrowser {
        name: "Chrome",

        paths: &["Google", "Chrome"],
        linux_paths: &["google-chrome"],

        service_name: "Chrome Safe Storage",

        macos_account: "Chrome",
        linux_secret_application: "chrome",
    },
    ChromiumBrowser {
        name: "Edge",

        paths: &["Microsoft", "Edge"],
        linux_paths: &["microsoft-edge"],

        service_name: "",

        macos_account: "",
        linux_secret_application: "edge",
    },
    ChromiumBrowser {
        name: "Brave",

        paths: &["BraveSoftware", "Brave-Browser"],
        linux_paths: &["brave-browser"],

        service_name: "Brave Safe Storage",

        macos_account: "Brave",
        linux_secret_application: "brave",
    },
    ChromiumBrowser {
        name: "Vivaldi",

        paths: &["Vivaldi"],
        linux_paths: &["vivaldi-stable"],

        service_name: "Vivaldi Safe Storage",

        macos_account: "Vivaldi",
        linux_secret_application: "vivaldi",
    },
];

pub struct ChromiumBrowser {
    pub name: &'static str,

    pub paths: &'static [&'static str],
    pub linux_paths: &'static [&'static str],

    pub service_name: &'static str,

    pub macos_account: &'static str,
    pub linux_secret_application: &'static str,
}
