use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginsFile {
    pub logins: Vec<Login>,
}

#[derive(Deserialize)]
pub struct Login {
    pub id: u32,

    pub hostname: String,

    #[serde(rename = "httpRealm")]
    pub http_realm: Option<String>,

    #[serde(rename = "formSubmitURL")]
    pub form_submit_url: String,

    #[serde(rename = "usernameField")]
    pub username_field: Option<String>,

    #[serde(rename = "passwordField")]
    pub password_field: Option<String>,

    #[serde(rename = "encryptedUsername")]
    pub encrypted_username: String,

    #[serde(rename = "encryptedPassword")]
    pub encrypted_password: String,

    #[serde(rename = "encType")]
    pub enc_type: u64,

    #[serde(rename = "timeCreated")]
    pub time_created: u64,

    #[serde(rename = "timeLastUsed")]
    pub time_last_used: u64,

    #[serde(rename = "timesUsed")]
    pub times_used: u64,
}
