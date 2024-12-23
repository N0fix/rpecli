use crate::import_export;
use crate::util::FileInfo;
use crate::utils::export::Exports;
use crate::utils::import::Imports;
use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use colored::Colorize;
use exe::{FileCharacteristics, VecPE, PE};
use serde::{Deserialize, Serialize};
use std::io::{stdout, Write};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone)]
struct FileExport {
    name: String,
    exports: Option<Exports>,
}

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

pub fn import_cmd(pe_filepaths: &Vec<String>, json_output: bool) {
    for file in pe_filepaths {
        if json_output {
            let Ok(image) = VecPE::from_disk_file(file) else {
                panic!("{}", alert_format!(format!("Could not read {}", file)));
            };
            let imp = Imports::parse(&image);
            write!(stdout(), "{}\n", serde_json::to_string(&imp.ok()).unwrap());
        } else {
            display_imports(file);
        }
    }
}

pub fn export_cmd(pe_filepaths: &Vec<String>, json_output: bool) {
    let mut result = Vec::<FileExport>::new();
    for file in pe_filepaths {
        if json_output {
            let Ok(image) = VecPE::from_disk_file(file) else {
                panic!("{}", alert_format!(format!("Could not read {}", file)));
            };
            let x = Path::new(file);
            let filename = match x.file_name() {
                Some(name) => name,
                None => {
                    eprintln!("{} is not a file", file);
                    continue;
                }
            };
            let exp = Exports::parse(&image);
            let f = FileInfo {
                input_filename: file.clone(),
                info: exp.ok(),
            };
            // result.push(FileExport {
            // name: filename.to_str().unwrap().to_string(),
            // exports: exp.ok(),
            // });

            write!(stdout(), "{}\n", serde_json::to_string(&f).unwrap());
        } else {
            display_exports(file);
        }
    }
}
