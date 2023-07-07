use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use colored::Colorize;
use exe::headers::ImageImportDescriptor;
use exe::{
    CCharString, ExportDirectory, HashData, ImageDirectoryEntry, ImageExportDirectory,
    ImageImportByName, ImportData, ImportDirectory, PETranslation, SectionCharacteristics, Thunk32,
    ThunkData, ThunkFunctions, VecPE, PE, RVA,
};
use ngrammatic::NgramBuilder;
use std::error::Error;
use std::f32::consts::E;
use std::ffi::CStr;

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
    println!(
        "\nimphash: {}",
        hex::encode(pe.calculate_imphash().unwrap())
    );

    Ok(())
}

pub fn get_export_map_test<'data, P: PE>(
    s: &ImageExportDirectory,
    pe: &'data P,
) -> Result<Vec<(u16, &'data str)>, Box<dyn Error>> {
    let mut result: Vec<(u16, &'data str)> = vec![];

    // let directory = pe.get_data_directory(ImageDirectoryEntry::Export)?;
    // let start = directory.virtual_address.clone();
    // let end = RVA(start.0 + directory.size);

    // let functions = s.get_functions(pe)?;
    let names = s.get_names(pe)?;
    let ordinals = s.get_name_ordinals(pe)?;

    for index in 0u32..s.number_of_names {
        let name_rva = names[index as usize];
        if name_rva.0 == 0 {
            continue;
        }

        let Ok(name_offset) = pe.translate(PETranslation::Memory(name_rva)) else {
            continue; /* we continue instead of returning the error to be greedy with parsing */
        };

        let Ok(name) = pe.get_cstring(name_offset, false, None) else {
            continue;
        };

        let ordinal = ordinals[index as usize];
        // let function = functions[ordinal as usize].parse_export(start, end);

        let name_str = match name.as_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        result.push((ordinal + 1, name_str));
    }
    // could also color API depending of usage w/ https://github.com/vadimkotov/winapi-json
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
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
        print!("\n{} - ", export_bin_name.bold());
    }

    let Ok(exports) = get_export_map_test(export_table, pe) else {
        println!("\n\t{}", "Invalid export table".red());
        return Ok(());
    };
    println!("{} exported function(s)", exports.len());
    let export_string: String = exports
        .iter()
        .map(|(_, s)| {
            if *s != "DllRegisterServer" {
                String::from(s.to_owned())
            } else {
                String::from("")
            }
        })
        .collect();
    let exports_ngram = NgramBuilder::new(export_string.as_str()).finish();
    let exports_ngram_vec: Vec<usize> = exports_ngram.grams.iter().map(|(x, y)| *y).collect();
    let avg: f32 = exports_ngram_vec.iter().sum::<usize>() as f32 / exports_ngram_vec.len() as f32;
    // println!("avg {}", avg);
    // exports_ngram_vec.sort_by(|a, b| b.1.cmp(a.1));
    // let weird_exports: bool = exports.len() >= 2 && exports_ngram_vec.first().unwrap().1 < &3;
    let weird_exports: bool = false; //avg < 1.30;
    for (ordinal, export) in &exports {
        println!(
            "\t {:>2} {}",
            ordinal,
            warn_format_if!(format!("{}", export), weird_exports)
        );
    }

    if weird_exports {
        println!("\n{}", "Weird looking exports".yellow());
    }

    println!("\nexphash: {}", hex::encode(calculate_exphash(pe).unwrap()));

    Ok(())
}

/// Calculate the exphash of the PE file.
fn calculate_exphash<P: PE>(pe: &P) -> Result<Vec<u8>, exe::Error> {
    let export_directory = ExportDirectory::parse(pe)?;
    let mut exphash_results = Vec::<String>::new();

    for &name_rva in export_directory.get_names(pe)? {
        let name_offset = pe.translate(PETranslation::Memory(name_rva))?;
        let name = pe.get_cstring(name_offset, false, None)?;
        exphash_results.push(name.as_str()?.to_string().clone());
    }

    Ok(exphash_results
        .join(",")
        .as_str()
        .to_lowercase()
        .as_bytes()
        .sha256())
}
