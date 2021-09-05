use neon::prelude::*;

mod browsers;
mod error;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function(
        "loginCredentials",
        browsers::js_login_credentials,
    )?;

    Ok(())
}
