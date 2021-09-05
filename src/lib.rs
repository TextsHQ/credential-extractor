use neon::prelude::*;

mod browsers;
mod error;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function(
        "searchLoginCredentials",
        browsers::js_search_login_credentials,
    )?;

    Ok(())
}
