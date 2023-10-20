use std::path::PathBuf;

use exe::VecPE;
use rpecli::utils::{export::pexp, import::pimp};

fn print_exports_as_json(pe_filepath: &PathBuf) {
    let Ok(image) = VecPE::from_disk_file(pe_filepath) else {
        panic!("Could not read file");
    };

    let x = match pexp(&image) {
        Some(exports) => exports,
        None => panic!("Invalid/Non existant exports"),
    };

    println!("{}", serde_json::to_string(&x).unwrap());
}

fn print_imports_as_json(pe_filepath: &PathBuf) {
    let Ok(image) = VecPE::from_disk_file(pe_filepath) else {
        panic!("Could not read file");
    };

    let x = match pimp(&image) {
        Some(imports) => imports,
        None => panic!("Invalid/Non existant imports"),
    };

    println!("{}", serde_json::to_string(&x).unwrap());
}

pub fn main() {
    if std::env::args().len() < 2 {
        println!(
            "{}",
            format!("Usage: {} <target>", std::env::args().nth(0).unwrap())
        );
    }

    print_imports_as_json(&std::path::PathBuf::from(std::env::args().nth(1).unwrap()));
    print_exports_as_json(&std::path::PathBuf::from(std::env::args().nth(1).unwrap()));
}
