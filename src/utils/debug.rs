use bytemuck::cast_slice;
use core::fmt;
use std::{ffi::CStr, io::Read, mem, slice};
// use bytemuck::Pod;
use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use colored::Colorize;
use dataview::Pod;
use exe::{Buffer, DebugDirectory, ImageDebugDirectory, ImageDirectoryEntry, VecPE, PE};

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ImageDebugType {
    Unknown = 0,
    Coff = 1,
    Codeview = 2,
    Fpo = 3,
    Misc = 4,
    Exception = 5,
    Fixup = 6,
    Omap_to_src = 7,
    Omap_from_src = 8,
    Borland = 9,
    Reserved10 = 10,
    Clsid = 11,
    Vc_feature = 12,
    Pogo = 13,
    Iltcg = 14,
    Mpx = 15,
    Repro = 16,
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
            7 => ImageDebugType::Omap_to_src,
            8 => ImageDebugType::Omap_from_src,
            9 => ImageDebugType::Borland,
            10 => ImageDebugType::Reserved10,
            11 => ImageDebugType::Clsid,
            12 => ImageDebugType::Vc_feature,
            13 => ImageDebugType::Pogo,
            14 => ImageDebugType::Iltcg,
            15 => ImageDebugType::Mpx,
            16 => ImageDebugType::Repro,
            _ => ImageDebugType::Unknown,
        }
    }
}

/// PGO information.
#[derive(Copy, Clone)]
pub struct Pgo<'a> {
    pub image: &'a [u32],
}
impl<'a> Pgo<'a> {
    /// Gets the underlying image.
    pub fn image(&self) -> &'a [u32] {
        self.image
    }
    /// Iterator over the PGO sections.
    pub fn iter(&self) -> PgoIter<'a> {
        let image = if self.image.len() >= 1 {
            &self.image[1..]
        } else {
            self.image
        };
        PgoIter { image }
    }
}
impl<'a> IntoIterator for Pgo<'a> {
    type Item = PgoItem<'a>;
    type IntoIter = PgoIter<'a>;
    fn into_iter(self) -> PgoIter<'a> {
        self.iter()
    }
}
impl<'a> fmt::Debug for Pgo<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}
/// Iterator over PGO sections.
#[derive(Clone)]
pub struct PgoIter<'a> {
    image: &'a [u32],
}
impl<'a> Iterator for PgoIter<'a> {
    type Item = PgoItem<'a>;
    fn next(&mut self) -> Option<PgoItem<'a>> {
        if self.image.len() >= 3 {
            let rva = self.image[0];
            let size = self.image[1];
            let name = CStr::from_bytes_until_nul(dataview::bytes(&self.image[2..])).unwrap();
            let len = name.to_str().unwrap().len() >> 2;
            self.image = &self.image[2 + len + 1..];
            Some(PgoItem { rva, size, name })
        } else {
            None
        }
    }
}
/// Describes a PGO section.
#[derive(Copy, Clone, Debug)]
pub struct PgoItem<'a> {
    pub rva: u32,
    pub size: u32,
    pub name: &'a CStr,
}

#[derive(Copy, Clone)]
pub enum CodeView<'a> {
    /// CodeView 2.0 debug information.
    Cv20 {
        image: &'a IMAGE_DEBUG_CV_INFO_PDB20,
        pdb_file_name: &'a CStr,
    },
    /// CodeView 7.0 debug information.
    Cv70 {
        image: &'a IMAGE_DEBUG_CV_INFO_PDB70,
        pdb_file_name: &'a CStr,
    },
}

impl<'a> CodeView<'a> {
    pub fn parse(pe: &VecPE) -> Option<CodeView> {
        const VC20: &[u8; 4] = b"NB10";
        const VC70: &[u8; 4] = b"RSDS";
        let Ok(debug_directory_check) = DebugDirectory::parse(pe) else {
            return None;
        };
        println!("Debug directory exists:");
        let debug_directory = debug_directory_check;
        let directory = pe.get_data_directory(ImageDirectoryEntry::Debug).unwrap();
        let imgdbgdir: &[ImageDebugDirectory] = pe
            .get_slice_ref(
                directory.virtual_address.0 as usize,
                directory.size as usize / std::mem::size_of::<ImageDebugDirectory>(),
            )
            .unwrap();

        for (i, d) in imgdbgdir.into_iter().enumerate() {
            println!("Entry {} type {:?}", i, ImageDebugType::from_u32(d.type_));
        }

        let cv = match ImageDebugType::from_u32(debug_directory.type_) {
            ImageDebugType::Codeview => {
                let start = debug_directory.address_of_raw_data;
                let mut x = pe
                    .read(
                        debug_directory.pointer_to_raw_data.into(),
                        debug_directory.size_of_data as usize,
                    )
                    .unwrap();
                let mut vc_type: [u8; 4] = [0, 0, 0, 0];

                x.read_exact(&mut vc_type);
                match &vc_type {
                    VC20 => {
                        let info = unsafe { &*(x.as_ptr() as *const IMAGE_DEBUG_CV_INFO_PDB20) };
                        let pdb_file_name = CStr::from_bytes_until_nul(&x[12..]).unwrap();
                        Some(CodeView::Cv20 {
                            image: info,
                            pdb_file_name: pdb_file_name,
                        })
                    }
                    VC70 => {
                        let info = unsafe { &*(x.as_ptr() as *const IMAGE_DEBUG_CV_INFO_PDB70) };
                        let pdb_file_name = CStr::from_bytes_until_nul(&x[20..]).unwrap();
                        Some(CodeView::Cv70 {
                            image: info,
                            pdb_file_name: pdb_file_name,
                        })
                    }
                    _ => {
                        // TODO : this is bad error mgt
                        None
                    }
                }
            }
            ImageDebugType::Pogo => {
                let start = debug_directory.address_of_raw_data;
                let mut x = pe
                    .read(
                        debug_directory.pointer_to_raw_data.into(),
                        debug_directory.size_of_data as usize,
                    )
                    .unwrap();
                let p = Pgo {
                    image: cast_slice(&x[0..]),
                };
                for item in p.iter() {
                    println!(
                        "{:#08x} {:#?} (size : {:#x})",
                        item.rva, item.name, item.size
                    );
                }
                // dbg!(p);
                // let qwe = 1;
                None
            }
            _ => {
                println!("{:?}", debug_directory.type_);
                // TODO : this is bad error mgt
                None
            }
        };

        cv
    }

    pub fn age(&self) -> u32 {
        match self {
            CodeView::Cv20 { image, .. } => image.Age,
            CodeView::Cv70 { image, .. } => image.Age,
        }
    }
    pub fn pdb_file_name(&self) -> &'a CStr {
        match self {
            CodeView::Cv20 { pdb_file_name, .. } => pdb_file_name,
            CodeView::Cv70 { pdb_file_name, .. } => pdb_file_name,
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: u16,
    pub data5: [u8; 4],
    pub data6: [u8; 2],
}
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct IMAGE_DEBUG_CV_INFO_PDB70 {
    // pub cv_signature: u32,
    pub signature: GUID,
    pub Age: u32,
    pub PdbFileName: [u8; 0],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct IMAGE_DEBUG_CV_INFO_PDB20 {
    pub Offset: u32,
    pub TimeDateStamp: u32,
    pub Age: u32,
    pub PdbFileName: [u8; 0],
}

impl fmt::Display for GUID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{{:X}-{:X}-{:X}-{:X}-{:X}{:X}}}",
            self.data1,
            self.data2,
            self.data3,
            self.data4,
            u32::from_be_bytes(self.data5),
            u16::from_be_bytes(self.data6)
        )
    }
}

const _: [(); 20] = [(); mem::size_of::<IMAGE_DEBUG_CV_INFO_PDB70>()]; // Unsized
const _: [(); 12] = [(); mem::size_of::<IMAGE_DEBUG_CV_INFO_PDB20>()]; // Unsized

unsafe impl Pod for IMAGE_DEBUG_CV_INFO_PDB70 {}
unsafe impl Pod for IMAGE_DEBUG_CV_INFO_PDB20 {}

impl<'a> fmt::Display for CodeView<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeView::Cv20 { image, .. } => {
                write!(f, "{:15}: {:#}\n", "Time date stamp", &image.TimeDateStamp).unwrap();
                write!(f, "{:15}: {:#}\n", "Age", &image.Age).unwrap();
            }
            CodeView::Cv70 { image, .. } => {
                write!(f, "{:15}: {:#}\n", "Signature", &image.signature).unwrap();
                write!(f, "{:15}: {:#}\n", "Age", &image.Age).unwrap();
            }
        }
        write!(
            f,
            "{:15}: \"{:#}\"\n",
            "PDB filename",
            self.pdb_file_name().to_str().unwrap()
        )
    }
}
// wip, should be using POD

// struct DebugEntry {
//     pub characteristics: u32,
//     pub time_date_stamp: u32,
//     pub major_version: u16,
//     pub minor_version: u16,
//     pub type_: ImageDebugType,
//     pub size_of_data: u32,
//     pub address_of_raw_data: u32,
//     pub pointer_to_raw_data: u32,
// }

// struct DebugEntries<'entries> {
//     entries: Vec<&'entries DebugEntry>,
// }

// enum DebugError {
//     MissingDirectory,
// }

// impl DebugEntries {
//     pub fn parse(pe: &VecPE) -> Result<DebugEntries, DebugError> {
//         let result = DebugEntries { entries: vec![] };
//         let Ok(debug_directory_check) = DebugDirectory::parse(pe) else {
//             return Err(DebugError::MissingDirectory);
//         };
//         let debug_directory = debug_directory_check;
//         let directory = pe.get_data_directory(ImageDirectoryEntry::Debug).unwrap();
//         let imgdbgdir: &[ImageDebugDirectory] = pe
//             .get_slice_ref(
//                 directory.virtual_address.0 as usize,
//                 directory.size as usize / std::mem::size_of::<ImageDebugDirectory>(),
//             )
//             .unwrap();

//         for (i, d) in imgdbgdir.into_iter().enumerate() {
//             let debug_entry: &DebugEntry = pe
//                 .get_slice_ref::<DebugEntry>(
//                     (directory.virtual_address.0 as usize + i * std::mem::size_of::<ImageDebugDirectory>())
//                         as usize,
//                     1,
//                 )
//                 .unwrap();
//             println!("Entry {} type {:?}", i, ImageDebugType::from_u32(d.type_));
//             result.entries.push(debug_entry);
//         }

//         Ok(result)
//     }
// }

pub fn display_debug_info(pe: &VecPE) {
    match CodeView::parse(pe) {
        Some(cv) => println!("{}", cv),
        None => println!(
            "{}",
            warn_format!("No debug directory (only tried to parse Code View)")
        ),
    }
}
