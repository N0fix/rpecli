
use colored::Colorize;
use exe::{FileCharacteristics, VecPE, PE};
use crate::utils::rsrc::display_rsrc;
use crate::{color_format_if, alert_format, warn_format, alert_format_if, warn_format_if};
use crate::import_export::{display_exports, display_imports};

pub fn display_ressource(pe_filepath: &str) {
    let Ok(image) = VecPE::from_disk_file(pe_filepath) else {
        println!("{}", alert_format!(format!("Could not read {}", pe_filepath)));
        return;
    };
    println!("Resources:\n{}", "=".repeat(if true { 80 } else { 0 }));
    display_rsrc(&image);
}