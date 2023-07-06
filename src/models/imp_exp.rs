use std::{fmt, collections::HashMap};

use exe::{FileCharacteristics, VecPE, PE, ImportDirectory, ImageDirectoryEntry, CCharString, ImportData, Error, ImageImportDescriptor};
use colored::Colorize;
use crate::{color_format_if, alert_format, warn_format, alert_format_if, warn_format_if, utils::debug};

#[derive(Debug)]
enum ImportError {
    MissingImportTable,
    BadDirectory(ImageDirectoryEntry)
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ImportError::MissingImportTable => write!(f, "Missing import table"),
            ImportError::BadDirectory(_) => write!(f, "Invalid import entries"),
        }
    }
}
impl std::error::Error for ImportError {}

struct Import {
    dll: Option<std::string::String>,
    name: Option<std::string::String>
}

impl Import {
    pub fn new(dll: std::string::String, name: std::string::String) -> Import {
        Import {
            dll: Some(dll.to_lowercase()),
            name: Some(name)
        }
    }

    pub fn get_dll_imp_name<P: PE>(pe: &P, image_import_descriptor: &ImageImportDescriptor) -> Result<std::string::String, exe::Error>{
        match image_import_descriptor.get_name(pe) {
            Ok(n) => match n.as_str() {
                Ok(s) => Ok(s.to_string().to_ascii_lowercase()),
                Err(e) => Err(e),
            },
            Err(e) => Err(e)
        }
    }

    pub fn parse<P: PE>(pe: &P) -> Result<(), ImportError> {
        let imps: HashMap<std::string::String, Import> = HashMap::<std::string::String, Import>::new();
        let import_directory = match ImportDirectory::parse(pe) {
            Ok(import_dir) => import_dir,
            Err(_) => return Err(ImportError::MissingImportTable)
        };
        for import in import_directory.descriptors {
            let dll_name = match Import::get_dll_imp_name(pe, import) {
                Ok(name) => Some(name),
                Err(_) => None,
            };

            // println!("\n{}", dll_name.bold());
            let import_entries = match import.get_imports(pe) {
                Ok(import_entries) => import_entries,
                Err(e) => {
                    println!(
                        "{}",
                        format!(
                            "{} (err: {})",
                            "Import entries are invalid. Is this a bad memory dump?",
                            { e }
                        )
                        .red()
                    );
                    return Err(exe::Error::BadDirectory(ImageDirectoryEntry::Import));
                }
            };
            for import_data in import_entries {
                let import_name = match import_data {
                    ImportData::Ordinal(x) => x.to_string(),
                    ImportData::ImportByName(s) => s.to_string(),
                };
                println!("\t{import_name}");
            }
        }
        println!("\nimphash: {}", hex::encode(pe.calculate_imphash().unwrap()));
    
        Ok(())
        
    }
}

