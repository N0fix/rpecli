use std::{
    collections::{HashMap, HashSet},
    ops::{Index, IndexMut},
};

use exe::{
    CCharString, ImageDirectoryEntry, ImageExportDirectory, PETranslation, ThunkData,
    ThunkFunctions, VecPE, PE, RVA,
};
use serde::{Deserialize, Serialize};

use crate::util::{ByteBuf, CChar_to_escaped_string};

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
    pub characteristics: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub export_file_name: String,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_names_ordinals: u32,
    pub timestamp: u32,
    pub entries: Vec<ExportEntry>,
}

impl Exports {
    pub fn parse<'data, P: PE>(pe: &'data P) -> Result<Exports, exe::Error> {
        let mut export_entries: Vec<ExportEntry> = vec![];
        let directory = pe.get_data_directory(ImageDirectoryEntry::Export)?;
        let start = directory.virtual_address.clone();
        let end = RVA(start.0.checked_add(directory.size).unwrap_or(0xFFFFFFFF));
        let s = ImageExportDirectory::parse(pe)?;
        let functions = s.get_functions(pe)?;
        let names = match s.get_names(pe) {
            Ok(e) => e,
            Err(e) => &[],
        };
        let ordinals = match s.get_name_ordinals(pe) {
            Ok(ordinals) => ordinals,
            Err(_) => &[],
        };

        // let export_name = match s.get_name(pe) {
        //     Ok(name) => match name.as_str() {
        //         Ok(s) => String::from(s),
        //         Err(_) => CChar_to_escaped_string(name),
        //     },
        //     Err(e) => String::from(format!("OOB{}", e)),
        // };
        let export_name = match pe.translate(PETranslation::Memory(s.name)) {
            Err(e) => return Err(e),
            Ok(a) => match pe.get_cstring(a, false, None) {
                Ok(s) => CChar_to_escaped_string(s),
                Err(_) => String::new(),
            },
        };

        let mut hm = HashMap::<u16, ExportEntry>::new();

        for index in 0u32..s.number_of_functions {
            let mut idx = index;
            if ordinals.get(index as usize).is_some() {
                idx = *ordinals.get(index as usize).unwrap() as u32;
            }
            let name = |names: &[RVA], idx: u32| -> Option<String> {
                let name_rva = names.get(idx as usize)?;
                let Ok(name_offset) = pe.translate(PETranslation::Memory(*name_rva)) else {
                    return None; /* we continue instead of returning the error to be greedy with parsing */
                };

                let Ok(name) = pe.get_cstring(name_offset, false, None) else {
                    return None;
                };

                let str = match name.as_str() {
                    Ok(s) => Some(String::from(s)),
                    Err(_) => Some(CChar_to_escaped_string(name)),
                };
                str
            }(names, index);

            let function = functions[idx as usize].parse_export(start, end);

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
            let exp_entry = ExportEntry {
                name: name,
                ordinal: s.base as u16 + idx as u16,
                rva: match function {
                    ThunkData::ForwarderString(rva) => Some(rva.0),
                    ThunkData::Function(rva) => Some(rva.0),
                    _ => None,
                },
                forwarded_name: forwarded_name,
            };
            hm.entry(s.base as u16 + idx as u16)
                .or_insert_with(|| exp_entry);
        }

        export_entries = hm.iter().map(|(_, entry)| entry.clone()).collect();

        export_entries.sort_by(|a, b| a.ordinal.cmp(&b.ordinal));

        Ok(Exports {
            characteristics: s.characteristics,
            major_version: s.major_version,
            minor_version: s.minor_version,
            export_file_name: export_name,
            base: s.base,
            number_of_functions: s.number_of_functions,
            number_of_names: s.number_of_names,
            address_of_functions: s.address_of_functions.0,
            address_of_names: s.address_of_names.0,
            address_of_names_ordinals: s.address_of_name_ordinals.0,
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
