use neon::prelude::*;

mod chromium;
mod firefox;

#[cfg(target_os = "macos")]
mod safari_keychain;

#[derive(Debug)]
pub struct Credential {
    pub browser: String,

    pub url: String,

    pub username: Option<String>,

    pub password: Password,

    pub username_element: Option<String>,

    pub password_element: Option<String>,

    pub times_used: Option<u64>,
}

#[derive(Debug)]
pub enum Password {
    Plaintext(String),
    Encrypted(Vec<u8>),
}

pub fn js_login_credentials(mut cx: FunctionContext) -> JsResult<JsArray> {
    let url = cx.argument::<JsString>(0)?.value(&mut cx);

    let browsers = [
        chromium::login_credentials(&url),
        firefox::login_credentials(&url),
        // #[cfg(target_os = "macos")]
        // safari_keychain::login_credentials(&url),
    ];

    let credentials: Vec<&Credential> = browsers
        .iter()
        .filter_map(|c| c.as_ref().ok())
        .flatten()
        .collect();

    let js_credentials = JsArray::new(&mut cx, credentials.len() as u32);

    for (i, credential) in credentials.iter().enumerate() {
        let js_credential = JsObject::new(&mut cx);

        let browser = cx.string(&credential.browser);
        let url = cx.string(&credential.url);

        match credential.password {
            Password::Encrypted(ref password) => {
                let mut encrypted_password = cx.buffer(password.len() as u32)?;

                cx.borrow_mut(&mut encrypted_password, |data| {
                    data.as_mut_slice().copy_from_slice(&password);
                });

                let t = cx.boolean(true);

                js_credential.set(&mut cx, "password", encrypted_password)?;
                js_credential.set(&mut cx, "passwordEncrypted", t)?;
            }
            Password::Plaintext(ref password) => {
                let password = cx.string(password);

                let t = cx.boolean(false);

                js_credential.set(&mut cx, "password", password)?;
                js_credential.set(&mut cx, "passwordEncrypted", t)?;
            }
        }

        js_credential.set(&mut cx, "browser", browser)?;
        js_credential.set(&mut cx, "url", url)?;

        if let Some(username) = &credential.username {
            let username = cx.string(username);
            js_credential.set(&mut cx, "username", username)?;
        }

        if let Some(username_element) = &credential.username_element {
            let username_element = cx.string(username_element);
            js_credential.set(&mut cx, "usernameElement", username_element)?;
        }

        if let Some(password_element) = &credential.password_element {
            let password_element = cx.string(password_element);
            js_credential.set(&mut cx, "passwordElement", password_element)?;
        }

        if let Some(times_used) = &credential.times_used {
            let times_used = cx.number(*times_used as f64);
            js_credential.set(&mut cx, "timesUsed", times_used)?;
        }

        js_credentials.set(&mut cx, i as u32, js_credential)?;
    }

    Ok(js_credentials)
}

pub fn js_decrypt_credential(mut cx: FunctionContext) -> JsResult<JsString> {
    let credential_obj = cx.argument::<JsObject>(0)?;

    let browser = credential_obj
        .get(&mut cx, "browser")?
        .downcast_or_throw::<JsString, _>(&mut cx)?
        .value(&mut cx);

    let encrypted_password_handle = credential_obj
        .get(&mut cx, "password")?
        .downcast_or_throw::<JsBuffer, _>(&mut cx)?;

    let mut encrypted_password = Vec::new();

    cx.borrow(&encrypted_password_handle, |data| {
        encrypted_password.extend_from_slice(data.as_slice());
    });

    // Reconstruct with minimal needed to decrypt
    let credential = Credential {
        browser: browser,
        url: "".to_string(),
        username: None,
        password: Password::Encrypted(encrypted_password),
        username_element: None,
        password_element: None,
        times_used: None,
    };

    let decrypted_password = match chromium::decrypt_credential(credential) {
        Ok(decrypted_password) => decrypted_password,
        Err(e) => cx.throw_error(e.to_string())?,
    };

    Ok(cx.string(decrypted_password))
}
