use crate::import_export;
use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use colored::Colorize;
use exe::{FileCharacteristics, VecPE, PE};

fn display_import_export(pe_filepath: &str) {
    let Ok(image) = VecPE::from_disk_file(pe_filepath) else {
        println!(
            "{}",
            alert_format!(format!("Could not read {}", pe_filepath))
        );
        return;
    };
    println!("Imports:\n{}", "=".repeat(if true { 80 } else { 0 }));
    import_export::display_imports(&image);
    println!("");
    println!("Exports:\n{}", "=".repeat(if true { 80 } else { 0 }));
    import_export::display_exports(&image);
}

fn display_imports(pe_filepath: &str) {
    let Ok(image) = VecPE::from_disk_file(pe_filepath) else {
        println!(
            "{}",
            alert_format!(format!("Could not read {}", pe_filepath))
        );
        return;
    };

    println!("Imports:\n{}", "=".repeat(if true { 80 } else { 0 }));
    import_export::display_imports(&image);
}

fn display_exports(pe_filepath: &str) {
    let Ok(image) = VecPE::from_disk_file(pe_filepath) else {
        println!(
            "{}",
            alert_format!(format!("Could not read {}", pe_filepath))
        );
        return;
    };

    println!("Exports:\n{}", "=".repeat(if true { 80 } else { 0 }));
    import_export::display_exports(&image);
}

pub fn import_export_cmd(pe_filepaths: &Vec<String>) {
    for file in pe_filepaths {
        display_import_export(file);
    }
}

pub fn import_cmd(pe_filepaths: &Vec<String>) {
    for file in pe_filepaths {
        display_imports(file);
    }
}

pub fn export_cmd(pe_filepaths: &Vec<String>) {
    for file in pe_filepaths {
        display_exports(file);
    }
}
