use crate::import_export::{display_exports, display_imports};
use crate::utils::rsrc::{display_rsrc, dump_rsrc};
use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use colored::Colorize;
use exe::{FileCharacteristics, VecPE, PE};

pub fn rsrc_cmd(pe_filepaths: &Vec<String>, display_hashes: bool, dump: bool) {
    for file in pe_filepaths {
        let Ok(image) = VecPE::from_disk_file(file) else {
            println!("{}", alert_format!(format!("Could not read {}", file)));
            continue;
        };
        println!("Resources:\n{}", "=".repeat(if true { 80 } else { 0 }));
        display_rsrc(&image, display_hashes);
        if dump {
            dump_rsrc(&image);
        }
    }
}
