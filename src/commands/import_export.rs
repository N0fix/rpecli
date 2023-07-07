use crate::import_export::{display_exports, display_imports};
use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use colored::Colorize;
use exe::{FileCharacteristics, VecPE, PE};

pub fn display_import_export(pe_filepath: &str) {
    let Ok(image) = VecPE::from_disk_file(pe_filepath) else {
        println!("{}", alert_format!(format!("Could not read {}", pe_filepath)));
        return;
    };
    println!("Imports:\n{}", "=".repeat(if true { 80 } else { 0 }));
    display_imports(&image);
    println!("");
    println!("Exports:\n{}", "=".repeat(if true { 80 } else { 0 }));
    display_exports(&image);
}
