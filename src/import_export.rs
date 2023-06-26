use colored::Colorize;
use exe::headers::ImageImportDescriptor;
use exe::{
    CCharString, ExportDirectory, ImageDirectoryEntry, ImageImportByName, ImportData,
    ImportDirectory, SectionCharacteristics, Thunk32, ThunkData, ThunkFunctions, VecPE, PE,
};

pub fn display_imports(pe: &VecPE) -> Result<(), exe::Error> {
    let import_directory = match ImportDirectory::parse(pe) {
        Ok(import_dir) => import_dir,
        Err(_) => {
            println!("{}", format!("{}", "No import table").yellow());
            return Err(exe::Error::BadDirectory(ImageDirectoryEntry::Import));
        }
    };
    for import in import_directory.descriptors {
        let dll_name = match import.get_name(pe) {
            Ok(n) => match n.as_str() {
                Ok(s) => s.to_string().to_ascii_lowercase(),
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        };
        println!("\n{}", dll_name.bold());
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

    Ok(())
}

pub fn display_exports(pe: &VecPE) -> Result<(), exe::Error> {
    let export_table = match ExportDirectory::parse(pe) {
        Ok(export_dir) => export_dir,
        Err(_) => {
            println!("{}", format!("{}", "No export table").yellow());
            return Err(exe::Error::BadDirectory(ImageDirectoryEntry::Export));
        }
    };
    if let Ok(name) = export_table.get_name(pe) {
        println!("\n{}", name.as_str().unwrap().bold())
    }
    let exports = match export_table.get_export_map(pe) {
        Ok(export_map) => export_map,
        Err(e) => {
            println!(
                "{}",
                format!(
                    "{} (err: {})",
                    "Export entries are invalid. Is this a bad memory dump?",
                    { e }
                )
                .red()
            );
            return Err(exe::Error::BadDirectory(ImageDirectoryEntry::Export));
        }
    };
    for export in exports {
        println!("\t{}", export.0);
    }

    Ok(())
}
