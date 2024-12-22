use std::io::{stdout, Write};

use crate::import_export::{display_exports, display_imports};
use crate::utils::rsrc::{display_rsrc, dump_rsrc, Resources};
use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use colored::Colorize;
use exe::{FileCharacteristics, VecPE, PE};

pub fn rsrc_cmd(pe_filepaths: &Vec<String>, display_hashes: bool, dump: bool, json: bool) {
    for file in pe_filepaths {
        let Ok(image) = VecPE::from_disk_file(file) else {
            println!("{}", alert_format!(format!("Could not read {}", file)));
            continue;
        };
        if json {
            let rsrc = Resources::parse(&image);
            write!(stdout(), "{}\n", serde_json::to_string(&rsrc.ok()).unwrap());
        } else {
            println!("Resources:\n{}", "=".repeat(if true { 80 } else { 0 }));
            display_rsrc(&image, display_hashes);
        }
        if dump {
            dump_rsrc(&image);
        }
    }
}
