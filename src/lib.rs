use neon::prelude::*;

mod browsers;
mod cryptos;
mod error;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    // cx.export_function("pullChromeCredentials", browserss::stub)?;

    Ok(())
}
