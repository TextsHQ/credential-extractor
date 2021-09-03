use neon::prelude::*;

mod chromium;

pub struct Credential {
    pub url: String,

    pub username: String,

    pub password: String,
}

pub fn js_search_login_credentials(mut cx: FunctionContext) -> JsResult<JsArray> {
    let url = cx.argument::<JsString>(0)?.value(&mut cx);

    let credentials = match chromium::search_login_credentials(&url) {
        Ok(credentials) => credentials,
        Err(e) => cx.throw_error(e.to_string())?,
    };

    let js_credentials = JsArray::new(&mut cx, credentials.len() as u32);

    for (i, credential) in credentials.iter().enumerate() {
        let js_credential = JsObject::new(&mut cx);

        let url = cx.string(&credential.url);
        let username = cx.string(&credential.username);
        let password = cx.string(&credential.password);

        js_credential.set(&mut cx, "url", url)?;
        js_credential.set(&mut cx, "username", username)?;
        js_credential.set(&mut cx, "password", password)?;

        js_credentials.set(&mut cx, i as u32, js_credential)?;
    }

    Ok(js_credentials)
}
