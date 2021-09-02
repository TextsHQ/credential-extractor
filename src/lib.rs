use neon::prelude::*;

mod utils;
mod error;
mod cryptos;
mod browsers;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {

    cx.export_function("pullChromeCredentials", browsers::stub)?;

    Ok(())
}
