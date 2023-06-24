use colored::Colorize;
use exe::headers::ImageImportDescriptor;
use exe::{
    CCharString, ExportDirectory, ImageImportByName, ImportData, ImportDirectory,
    SectionCharacteristics, Thunk32, ThunkData, ThunkFunctions, VecPE, PE,
};

pub fn display_imports(pe: &VecPE) -> Result<(), exe::Error> {
    let import_directory = ImportDirectory::parse(pe).unwrap();
    for import in import_directory.descriptors {
        let dll_name = match import.get_name(pe) {
            Ok(n) => match n.as_str() {
                Ok(s) => s.to_string().to_ascii_lowercase(),
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        };
        println!("\n{}", dll_name.bold());
        let import_entries = import.get_imports(pe)?;
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
    let export_directory = ExportDirectory::parse(pe);
    match export_directory.is_ok() {
        true => {
            let export_table = export_directory.unwrap();
            if let Ok(name) = export_table.get_name(pe) {
                println!("\n{}", name.as_str().unwrap().bold())
            }
            let exports = export_table.get_export_map(pe).unwrap();
            for export in exports {
                println!("\t{}", export.0);
            }
        }
        false => println!("No exports"),
    };

    Ok(())
}
