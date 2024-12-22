use std::{ffi::CStr, fmt, io::Read, mem};

use crate::utils::debug::{DebugEntry, ImageDebugType, ReadError, ReadFrom};
use dataview::Pod;
use exe::{DebugDirectory, ImageDebugDirectory, ImageDirectoryEntry, VecPE, PE};
use pkbuffer::Buffer;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub enum CodeView<'a> {
    /// CodeView 2.0 debug information.
    Cv20 {
        image: IMAGE_DEBUG_CV_INFO_PDB20,
        pdb_file_name: &'a str,
    },
    /// CodeView 7.0 debug information.
    Cv70 {
        image: IMAGE_DEBUG_CV_INFO_PDB70,
        pdb_file_name: &'a str,
    },
}

impl<'pe> ReadFrom<'pe> for CodeView<'pe> {
    fn read_debug_from(
        debug_directory: &DebugEntry,
        pe: &'pe VecPE,
    ) -> Result<CodeView<'pe>, ReadError> {
        const VC20: &[u8; 4] = b"NB10";
        const VC70: &[u8; 4] = b"RSDS";

        let cv = match ImageDebugType::from_u32(debug_directory.type_) {
            ImageDebugType::Codeview => {
                let mut x = pe
                    .read(
                        debug_directory.pointer_to_raw_data as usize,
                        debug_directory.size_of_data as usize,
                    )
                    .unwrap();
                let mut vc_type: [u8; 4] = [0, 0, 0, 0];

                x.read_exact(&mut vc_type);
                match &vc_type {
                    VC20 => {
                        let info = unsafe { &*(x.as_ptr() as *const IMAGE_DEBUG_CV_INFO_PDB20) };
                        let pdb_file_name = CStr::from_bytes_until_nul(&x[12..])
                            .unwrap()
                            .to_str()
                            .unwrap();
                        CodeView::Cv20 {
                            image: info.to_owned(),
                            pdb_file_name: pdb_file_name,
                        }
                    }
                    VC70 => {
                        let info = unsafe { &*(x.as_ptr() as *const IMAGE_DEBUG_CV_INFO_PDB70) };
                        let pdb_file_name = CStr::from_bytes_until_nul(&x[20..])
                            .unwrap()
                            .to_str()
                            .unwrap();
                        CodeView::Cv70 {
                            image: info.to_owned(),
                            pdb_file_name: pdb_file_name,
                        }
                    }
                    _ => {
                        // TODO : this is bad error mgt
                        return Err(ReadError::InvalidType);
                    }
                }
            }
            _ => return Err(ReadError::InvalidType),
        };

        Ok(cv)
    }
}

impl<'a> CodeView<'a> {
    pub fn pdb_file_name(&self) -> &'a str {
        match self {
            CodeView::Cv20 { pdb_file_name, .. } => pdb_file_name,
            CodeView::Cv70 { pdb_file_name, .. } => pdb_file_name,
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
#[repr(C)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 2],
    pub data5: [u8; 4],
    pub data6: [u8; 2],
}
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
#[repr(C)]
pub struct IMAGE_DEBUG_CV_INFO_PDB70 {
    // pub cv_signature: u32,
    pub signature: GUID,
    pub Age: u32,
    pub PdbFileName: [u8; 0],
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
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
            "{{{:08X}-{:04X}-{:04X}-{:04X}-{:08X}{:04X}}}",
            self.data1,
            self.data2,
            self.data3,
            u16::from_be_bytes(self.data4),
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
                write!(f, "  CodeView (v20)\n")?;
                write!(
                    f,
                    "    {:15}: {:#}\n",
                    "Time date stamp", &image.TimeDateStamp
                )?;
                write!(f, "    {:15}: {:#}\n", "Age", &image.Age)?;
            }
            CodeView::Cv70 { image, .. } => {
                write!(f, "  CodeView (v70)\n")?;
                write!(f, "    {:15}: {:#}\n", "Signature", &image.signature)?;
                write!(f, "    {:15}: {:#}\n", "Age", &image.Age)?;
            }
        }
        write!(
            f,
            "    {:15}: \"{:#}\"\n",
            "PDB filename",
            self.pdb_file_name()
        )
    }
}
