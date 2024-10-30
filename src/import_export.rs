use crate::utils::export::Exports;
use crate::utils::import::Imports;
// use crate::utils::import::Imports;
use crate::utils::timestamps::format_timestamp;
use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use colored::Colorize;
use dataview::PodMethods;
use exe::{
    CCharString, ExportDirectory, HashData, ImageDirectoryEntry, ImageExportDirectory,
    ImageImportByName, ImportData, ImportDirectory, PETranslation, SectionCharacteristics, Thunk32,
    ThunkData, ThunkFunctions, VecPE, PE, RVA,
};

pub fn display_imports(pe: &VecPE) -> Result<(), exe::Error> {
    let x = pe.clone();
    let import_directory = match ImportDirectory::parse(pe) {
        Ok(import_dir) => import_dir,
        Err(_) => {
            println!("{}", format!("{}", "No import table").yellow());
            return Err(exe::Error::BadDirectory(ImageDirectoryEntry::Import));
        }
    };

    let Ok(imports) = Imports::parse(pe) else {
        println!("\n\t{}", "Invalid import table".red());
        return Ok(());
    };

    for import in &imports.modules {
        println!("\n{}", import.name.bold());
        for imported_fn in &import.imports {
            print!("\t{}", imported_fn.name);
            if imported_fn.import_by_ordinal {
                print!("(Import by ordinal)");
            }
            println!("");
        }
    }

    println!(
        "\nimphash: {}",
        hex::encode(pe.calculate_imphash().unwrap())
    );

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
        let export_bin_name = match name.as_str() {
            Ok(s) => String::from(s),
            Err(_) => "Invalid non ASCII export binary name".red().to_string(),
        };
        print!("\n\"{}\" => ", export_bin_name.bold());
    }

    let Ok(exports) = Exports::parse(pe) else {
        println!("\n\t{}", "Invalid export table".red());
        return Ok(());
    };

    // let mut exphash_results = Vec::<String>::new();

    println!("{} exported function(s)", exports.entries.len());
    let empty_str = warn_format!("(EXPORT HAS NO NAME)").to_string();
    for entry in &exports.entries {
        // if entry.name.is_some() {
        //     let n = entry.name.clone().unwrap();
        //     exphash_results.push(n);
        // }
        println!(
            "\t {:>2} => {} {}",
            &entry.ordinal,
            format!(
                "{}",
                &entry.name.as_ref().or_else(|| Some(&empty_str)).unwrap()
            ),
            match &entry.forwarded_name {
                Some(name) => warn_format!(format!("(Forwarded export) => {}", name)),
                None => "".normal(),
            },
        );
    }

    // println!("\nexphash: {}", hex::encode(exphash_results
    //     .join(",")
    //     .as_str()
    //     .to_lowercase()
    //     .as_bytes()
    //     .md5()));
    println!(
        "Export timestamp: {}",
        format_timestamp(export_table.time_date_stamp as i64)
    );

    Ok(())
}

// Calculate the exphash of the PE file.
// fn calculate_exphash<P: PE>(pe: &P) -> Result<Vec<u8>, exe::Error> {
//     let export_directory = ExportDirectory::parse(pe)?;

//     for &name_rva in export_directory.get_names(pe)? {
//         let name_offset = pe.translate(PETranslation::Memory(name_rva))?;
//         let name = pe.get_cstring(name_offset, false, None)?;
//         exphash_results.push(name.as_str()?.to_string().clone());
//     }

//     Ok()
// }
