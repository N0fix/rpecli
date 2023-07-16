use bytemuck::cast_slice;
use chrono::{NaiveDateTime, Utc};
use core::fmt;
use pkbuffer::Castable;
use std::{ffi::CStr, fmt::Display, io::Read, mem, slice};
// use bytemuck::Pod;
use crate::{
    alert_format, alert_format_if, color_format_if, utils::timestamps::format_timestamp,
    warn_format, warn_format_if,
};
use colored::Colorize;
use dataview::Pod;
use exe::{Buffer, DebugDirectory, ImageDebugDirectory, ImageDirectoryEntry, VecPE, PE};

use super::debug_entries::{codeview::CodeView, pgo::Pgo};

#[derive(Debug)]
pub enum ReadError {
    InvalidType,
}

#[derive(Debug)]
pub enum DebugDirectoryParseError {
    MissingDirectory,
}

pub trait ReadFrom<'data> {
    fn read_debug_from(debug_entry: &DebugEntry, pe: &'data VecPE) -> Result<Self, ReadError>
    where
        Self: Sized;
}

pub enum DebugEntryEnum<'data> {
    Unknown,
    Codeview(CodeView<'data>),
    Pogo(Pgo<'data>),
}

#[derive(Copy, Clone, Debug)]
pub enum ImageDebugType {
    Unknown = 0,
    Coff = 1,
    Codeview = 2,
    Fpo = 3,
    Misc = 4,
    Exception = 5,
    Fixup = 6,
    OmapToSrc = 7,
    OmapFromSrc = 8,
    Borland = 9,
    Reserved10 = 10,
    Clsid = 11,
    VcFeature = 12,
    Pogo,
    Iltcg = 14,
    Mpx = 15,
    Repro = 16,
    ExDllCharacteristics = 20,
}
impl ImageDebugType {
    /// Convert the [`u32`](u32) value to an `ImageDebugType` enum variant.
    pub fn from_u32(u: u32) -> Self {
        match u {
            1 => ImageDebugType::Coff,
            2 => ImageDebugType::Codeview,
            3 => ImageDebugType::Fpo,
            4 => ImageDebugType::Misc,
            5 => ImageDebugType::Exception,
            6 => ImageDebugType::Fixup,
            7 => ImageDebugType::OmapToSrc,
            8 => ImageDebugType::OmapFromSrc,
            9 => ImageDebugType::Borland,
            10 => ImageDebugType::Reserved10,
            11 => ImageDebugType::Clsid,
            12 => ImageDebugType::VcFeature,
            13 => ImageDebugType::Pogo,
            14 => ImageDebugType::Iltcg,
            15 => ImageDebugType::Mpx,
            16 => ImageDebugType::Repro,
            20 => ImageDebugType::ExDllCharacteristics,
            _ => ImageDebugType::Unknown,
        }
    }
}

// wip, should be using POD
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Castable, Debug)]
pub struct DebugEntry {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub type_: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

impl Display for DebugEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "  Type      : {:?}",
            ImageDebugType::from_u32(self.type_)
        )?;
        writeln!(
            f,
            "  Timestamp : {}",
            format_timestamp(self.time_date_stamp as i64)
        )
    }
}

impl<'pe> DebugEntry {
    pub fn parse(&self, pe: &'pe VecPE) -> Result<DebugEntryEnum<'pe>, ReadError> {
        Ok(match ImageDebugType::from_u32(self.type_) {
            ImageDebugType::Codeview => {
                DebugEntryEnum::Codeview(CodeView::read_debug_from(self, pe)?)
            }
            ImageDebugType::Pogo => DebugEntryEnum::Pogo(Pgo::read_debug_from(self, pe)?),
            _ => DebugEntryEnum::Unknown,
        })
    }
}

pub struct DebugEntries<'entries> {
    pub entries: Vec<&'entries DebugEntry>,
}

impl DebugEntries<'_> {
    pub fn parse(pe: &VecPE) -> Result<DebugEntries, DebugDirectoryParseError> {
        let mut result = DebugEntries { entries: vec![] };
        let Ok(debug_directory_check) = DebugDirectory::parse(pe) else {
            return Err(DebugDirectoryParseError::MissingDirectory);
        };
        let directory = pe.get_data_directory(ImageDirectoryEntry::Debug).unwrap();
        let imgdbgdir: &[DebugEntry] = pe
            .get_slice_ref(
                directory.virtual_address.0 as usize,
                directory.size as usize / std::mem::size_of::<DebugEntry>(),
            )
            .unwrap();
        for debug_entry in imgdbgdir {
            result.entries.push(debug_entry);
        }

        Ok(result)
    }
}

pub fn display_debug_info(pe: &VecPE) {
    match DebugEntries::parse(pe) {
        Ok(entries) => {
            // println!("{} debug entries", entries.entries.len());
            for (i, entry) in entries.entries.iter().enumerate() {
                println!("{}", format!("Entry {}:\n{}", i + 1, entry).bold());
                match entry.parse(pe) {
                    Ok(debug_entry) => match debug_entry {
                        DebugEntryEnum::Codeview(cv) => {
                            println!("{}", cv);
                        }
                        DebugEntryEnum::Pogo(pgo) => {
                            println!("{}", pgo);
                        }
                        _ => {
                            println!(
                                "{}",
                                warn_format!(format!(
                                    "  Entry of type {:?} is not supported for display\n",
                                    ImageDebugType::from_u32(entry.type_)
                                ))
                            );
                        }
                    },
                    Err(_) => println!("{}", alert_format!("Invalid entry")),
                };
            }
        }
        Err(e) => {
            match e {
                DebugDirectoryParseError::MissingDirectory => {
                    println!("{}", warn_format!("No Debug directory"))
                }
            };
        }
    };
}
