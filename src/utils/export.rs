use exe::{
    CCharString, ImageDirectoryEntry, ImageExportDirectory, PETranslation, ThunkData,
    ThunkFunctions, VecPE, PE, RVA,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct ExportEntry {
    pub name: Option<String>,
    pub ordinal: u16,
    /// None if export by Ordinal
    /// Forwarded name RVA if forwarded is not None
    /// Function RVA if forwarded is false
    pub rva: Option<u32>,
    pub forwarded_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct Exports {
    pub name: String,
    pub timestamp: u32,
    pub entries: Vec<ExportEntry>,
}

impl Exports {
    pub fn parse<'data, P: PE>(pe: &'data P) -> Result<Exports, exe::Error> {
        let mut export_entries: Vec<ExportEntry> = vec![];
        let directory = pe.get_data_directory(ImageDirectoryEntry::Export)?;
        let start = directory.virtual_address.clone();
        let end = RVA(start.0 + directory.size);
        let s = ImageExportDirectory::parse(pe)?;
        let functions = s.get_functions(pe)?;
        let names = s.get_names(pe)?;
        let ordinals = s.get_name_ordinals(pe)?;

        let export_name = match s.get_name(pe) {
            Ok(name) => String::from(name.as_str()?),
            Err(_) => String::new(),
        };

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
            let function = functions[ordinal as usize].parse_export(start, end);
            let name_str = match name.as_str() {
                Ok(s) => Some(String::from(s)),
                Err(_) => None,
            };
            let forwarded_name = match function {
                ThunkData::ForwarderString(rva) => match pe.translate(PETranslation::Memory(rva)) {
                    Ok(addr) => match pe.get_cstring(addr, false, None) {
                        Ok(name) => Some(String::from(name.as_str()?)),
                        Err(_) => panic!("INVALID NAME"),
                    },
                    Err(_) => None,
                },
                _ => None,
            };
            export_entries.push(ExportEntry {
                name: name_str,
                ordinal: s.base as u16 + ordinal,
                rva: match function {
                    ThunkData::ForwarderString(rva) => Some(rva.0),
                    ThunkData::Function(rva) => Some(rva.0),
                    _ => None,
                },
                forwarded_name: forwarded_name,
            });
        }

        export_entries.sort_by(|a, b| a.ordinal.cmp(&b.ordinal));

        Ok(Exports {
            name: export_name,
            timestamp: s.time_date_stamp,
            entries: export_entries,
        })
    }
}

pub fn pexp(pe: &VecPE) -> Option<Exports> {
    match Exports::parse(pe) {
        Ok(exports) => Some(exports),
        Err(_) => None,
    }
}
