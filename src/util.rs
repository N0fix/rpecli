use std::{error::Error, u64::MAX};

use exe::{ImageSubsystem, VecPE, PE};

use crate::utils::pe_size::get_pe_file_size;

pub fn round_to_pe_sz(pe: &VecPE, value: usize) -> usize {
    usize::min(value, get_pe_file_size(pe))
}

pub fn round_to_pe_sz_with_offset<P: PE>(pe: &P, offset: usize, value: usize) -> usize {
    let pe_sz = get_pe_file_size(pe);
    match offset + value > pe_sz {
        true => pe_sz - offset,
        false => value,
    }
}

pub fn safe_read<P: PE>(pe: &P, offset: usize, size: usize) -> &[u8] {
    let pe_sz = get_pe_file_size(pe);
    if offset >= pe_sz {
        return pe.read(0, 0).unwrap();
    }

    let safe_size = round_to_pe_sz_with_offset(pe, offset, size);
    pe.read(offset, safe_size).unwrap()
}

pub struct ImageSubsystem_rpecli(pub ImageSubsystem);

impl From<u16> for ImageSubsystem_rpecli {
    fn from(value: u16) -> Self {
        match value {
            1 => ImageSubsystem_rpecli(ImageSubsystem::Native),
            2 => ImageSubsystem_rpecli(ImageSubsystem::WindowsGUI),
            3 => ImageSubsystem_rpecli(ImageSubsystem::WindowsCUI),
            4 => ImageSubsystem_rpecli(ImageSubsystem::OS2CUI),
            5 => ImageSubsystem_rpecli(ImageSubsystem::POSIXCUI),
            6 => ImageSubsystem_rpecli(ImageSubsystem::NativeWindows),
            7 => ImageSubsystem_rpecli(ImageSubsystem::WindowsCEGUI),
            8 => ImageSubsystem_rpecli(ImageSubsystem::EFIApplication),
            9 => ImageSubsystem_rpecli(ImageSubsystem::EFIBootServiceDriver),
            10 => ImageSubsystem_rpecli(ImageSubsystem::EFIRuntimeDriver),
            11 => ImageSubsystem_rpecli(ImageSubsystem::EFIROM),
            12 => ImageSubsystem_rpecli(ImageSubsystem::XBox),
            13 => ImageSubsystem_rpecli(ImageSubsystem::WindowsBootApplication),
            14 => ImageSubsystem_rpecli(ImageSubsystem::XBoxCodeCatalog),
            _ => ImageSubsystem_rpecli(ImageSubsystem::Unknown),
        }
    }
}

impl ImageSubsystem_rpecli {
    pub fn as_string(&self) -> String {
        match self.0 {
            ImageSubsystem::Unknown => String::from("Unknown"),
            ImageSubsystem::Native => String::from("Native"),
            ImageSubsystem::WindowsGUI => String::from("WindowsGUI"),
            ImageSubsystem::WindowsCUI => String::from("WindowsCUI"),
            ImageSubsystem::OS2CUI => String::from("OS2CUI"),
            ImageSubsystem::POSIXCUI => String::from("POSIXCUI"),
            ImageSubsystem::NativeWindows => String::from("NativeWindows"),
            ImageSubsystem::WindowsCEGUI => String::from("WindowsCEGUI"),
            ImageSubsystem::EFIApplication => String::from("EFIApplication"),
            ImageSubsystem::EFIBootServiceDriver => String::from("EFIBootServiceDriver"),
            ImageSubsystem::EFIRuntimeDriver => String::from("EFIRuntimeDriver"),
            ImageSubsystem::EFIROM => String::from("EFIROM"),
            ImageSubsystem::XBox => String::from("XBox"),
            ImageSubsystem::WindowsBootApplication => String::from("WindowsBootApplication"),
            ImageSubsystem::XBoxCodeCatalog => String::from("XBoxCodeCatalog"),
        }
    }
}

pub fn get_subsystem<P: PE>(pe: &P) -> Result<ImageSubsystem_rpecli, Box<dyn Error>> {
    let arch = pe.get_arch()?;
    match arch {
        exe::Arch::X86 => Ok(ImageSubsystem_rpecli::from(
            pe.get_nt_headers_32()?.optional_header.subsystem,
        )),
        exe::Arch::X64 => Ok(ImageSubsystem_rpecli::from(
            pe.get_nt_headers_64()?.optional_header.subsystem,
        )),
    }
}
