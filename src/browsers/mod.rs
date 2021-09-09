use neon::prelude::*;

mod chromium;

pub struct Credential {
    pub browser: String,

    pub url: String,

    pub username: String,

    pub encrypted_password: Vec<u8>,
}

pub fn js_login_credentials(mut cx: FunctionContext) -> JsResult<JsArray> {
    let url = cx.argument::<JsString>(0)?.value(&mut cx);

    let credentials = match chromium::login_credentials(&url) {
        Ok(credentials) => credentials,
        Err(e) => cx.throw_error(e.to_string())?,
    };

    let js_credentials = JsArray::new(&mut cx, credentials.len() as u32);

    for (i, credential) in credentials.iter().enumerate() {
        let js_credential = JsObject::new(&mut cx);

        let browser = cx.string(&credential.browser);
        let url = cx.string(&credential.url);
        let username = cx.string(&credential.username);
        let mut encrypted_password = cx.buffer(credential.encrypted_password.len() as u32)?;

        cx.borrow_mut(&mut encrypted_password, |data| {
            data.as_mut_slice()
                .copy_from_slice(&credential.encrypted_password);
        });

        js_credential.set(&mut cx, "browser", browser)?;
        js_credential.set(&mut cx, "url", url)?;
        js_credential.set(&mut cx, "username", username)?;
        js_credential.set(&mut cx, "encrypted_password", encrypted_password)?;

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
        .get(&mut cx, "encrypted_password")?
        .downcast_or_throw::<JsBuffer, _>(&mut cx)?;

    let mut encrypted_password = Vec::new();

    cx.borrow(&encrypted_password_handle, |data| {
        encrypted_password.extend_from_slice(data.as_slice());
    });

    // Reconstruct with minimal needed to decrypt
    let mut credential = Credential {
        browser: browser,
        url: "".to_string(),
        username: "".to_string(),
        encrypted_password,
    };

    let decrypted_password = match chromium::decrypt_credential(&mut credential) {
        Ok(decrypted_password) => decrypted_password,
        Err(e) => cx.throw_error(e.to_string())?,
    };

    Ok(cx.string(decrypted_password))
}
