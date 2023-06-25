use core::fmt;
use std::{io::Read, mem, slice, ffi::CStr};
// use bytemuck::Pod;
use exe::{DebugDirectory, VecPE, ImageDebugType, Buffer};
use dataview::Pod;

#[derive(Copy, Clone)]
pub enum CodeView<'a> {
	/// CodeView 2.0 debug information.
	Cv20 { image: &'a IMAGE_DEBUG_CV_INFO_PDB20, pdb_file_name: &'a CStr },
	/// CodeView 7.0 debug information.
	Cv70 { image: &'a IMAGE_DEBUG_CV_INFO_PDB70, pdb_file_name: &'a CStr },
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
    pub PdbFileName: [u8; 0]
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
        write!(f, "{{{:X}-{:X}-{:X}-{:X}-{:X}{:X}}}",  self.data1, self.data2, self.data3, self.data4, u32::from_be_bytes(self.data5), u16::from_be_bytes(self.data6))
    }
}

const _: [(); 20] = [(); mem::size_of::<IMAGE_DEBUG_CV_INFO_PDB70>()]; // Unsized
const _: [(); 12] = [(); mem::size_of::<IMAGE_DEBUG_CV_INFO_PDB20>()]; // Unsized

unsafe impl Pod for IMAGE_DEBUG_CV_INFO_PDB70 {}
unsafe impl Pod for IMAGE_DEBUG_CV_INFO_PDB20 {}
impl<'a> CodeView<'a> {
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
impl<'a> fmt::Display for CodeView<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			CodeView::Cv20 { image, .. } => {
                write!(f, "{:15}: {:#}\n", "Time date stamp", &image.TimeDateStamp).unwrap();
                write!(f, "{:15}: {:#}\n", "Age", &image.Age).unwrap();
			},
			CodeView::Cv70 { image, .. } => {
                write!(f, "{:15}: {:#}\n", "Signature", &image.signature).unwrap();
                write!(f, "{:15}: {:#}\n", "Age", &image.Age).unwrap();
			},
		}
        write!(f, "{:15}: \"{:#}\"\n", "PDB filename", self.pdb_file_name().to_str().unwrap())
    }
}

pub fn display_debug_info(pe: &VecPE) {
    const VC20: &[u8; 4] = b"NB10";
    const VC70: &[u8; 4] = b"RSDS";
    let debug_directory_check = DebugDirectory::parse(pe).unwrap();

    let debug_directory = debug_directory_check;
    match ImageDebugType::from_u32(debug_directory.type_) {
        ImageDebugType::CodeView => {
            let start = debug_directory.address_of_raw_data;
            let mut x = pe.read(debug_directory.pointer_to_raw_data.into(), debug_directory.size_of_data  as usize).unwrap();
            let mut vc_type: [u8; 4] = [0,0,0,0];
        
            x.read_exact(&mut vc_type);
            let cv = match &vc_type {
                VC20 => {
                    let info = unsafe { &*(x.as_ptr() as *const IMAGE_DEBUG_CV_INFO_PDB20) };
                    let pdb_file_name = CStr::from_bytes_with_nul(&x[12..]).unwrap();
                    CodeView::Cv20 { image: info, pdb_file_name: pdb_file_name }
                },
                VC70 => {
                    let info = unsafe { &*(x.as_ptr() as *const IMAGE_DEBUG_CV_INFO_PDB70) };
                    let pdb_file_name = CStr::from_bytes_with_nul(&x[20..]).unwrap();
                    CodeView::Cv70 { image: info, pdb_file_name: pdb_file_name }
                },
                _ => panic!("Unknown debug VC mode"),
            };
            println!("{:#}", cv);
        },
        _ => {},
    };
}