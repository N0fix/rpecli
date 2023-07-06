use std::{collections::HashMap, mem};

use exe::{
    VSFixedFileInfo, VSStringFileInfo, VSStringTable, VSVersionInfo, VecPE, WCharString, PE, pe, ImageDataDirectory, RVA, Address,
};
use term_table::row::Row;
use term_table::table_cell::TableCell;
use term_table::Table;

use crate::util::safe_read;
use authenticode::{AttributeCertificateIterator, PeTrait, PeOffsets};
use cms::signed_data::SignerIdentifier;
fn string_vec(string_file_info: &VSStringFileInfo) -> Result<Vec<(String, String)>, exe::Error> {
    let mut result = Vec::<(String, String)>::new();

    for entry in &string_file_info.children[0].children {
        let entry_key = entry.header.key.as_u16_str()?;
        let entry_value = entry.value.as_u16_str()?;

        result.push((
            entry_key.as_ustr().to_string_lossy(),
            entry_value.as_ustr().to_string_lossy(),
        ));
    }

    Ok(result)
}

pub fn display_version_info(pe: &VecPE) {
    let vs_version_check = VSVersionInfo::parse(pe);
    let vs_version = vs_version_check.unwrap();
    if let Some(string_file_info) = vs_version.string_file_info {
        let infos = string_vec(&string_file_info).unwrap();

        let string_map = string_file_info.children[0].string_map().unwrap();
        let mut table = Table::new();
        table.max_column_width = term_size::dimensions()
            .or_else(|| Some((4000, 4000)))
            .unwrap()
            .0;
        for (key, value) in infos.into_iter() {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(key, 1, term_table::table_cell::Alignment::Left),
                TableCell::new_with_alignment(value, 1, term_table::table_cell::Alignment::Right),
            ]));
        }
        println!("{}", table.render());
    } else {
        panic!("couldn't get string file info");
    }
}


struct PEForParsing {
    pe: exe::pe::VecPE
}

impl PeTrait for PEForParsing {
    fn data(&self) -> &[u8] {
        self.pe.get_buffer().as_ref()
    }

    fn num_sections(&self) -> usize {
        match self.pe.get_section_table() {
            Ok(sec_tbl) => sec_tbl.len(),
            Err(_) => 0,
        }
    }

    fn section_data_range(
        &self,
        index: usize,
    ) -> Result<std::ops::Range<usize>, authenticode::PeOffsetError> {
        let Ok(sections) = self.pe.get_section_table() else {
            return Err(authenticode::PeOffsetError);
        };
        let Some(section) = sections.get(index) else {
            return Err(authenticode::PeOffsetError);
        };
        Ok(section.pointer_to_raw_data.0 as usize..(section.size_of_raw_data + section.pointer_to_raw_data.0) as usize)
    }

    fn certificate_table_range(
        &self,
    ) -> Result<Option<std::ops::Range<usize>>, authenticode::PeOffsetError> {
        let security_dir = match self.pe.get_data_directory(exe::ImageDirectoryEntry::Security) {
            Ok(security_dir) => security_dir,
            Err(_) => {
                return Ok(None);
            }
        };
        Ok(Some(security_dir.virtual_address.0 as usize..(security_dir.virtual_address.0 + security_dir.size) as usize))
    }

    fn offsets(&self) -> Result<authenticode::PeOffsets, authenticode::PeOffsetError> {
        // Hash from the security data directory to the end of the header.
        let Ok(arch) = self.pe.get_arch() else {
            return Err(authenticode::PeOffsetError);
        };

        let size_of_headers = match arch {
            exe::Arch::X86 => mem::size_of::<exe::ImageNTHeaders32>(),
            exe::Arch::X64 => mem::size_of::<exe::ImageNTHeaders64>(),
        };
        
        let Ok(security_dir) = self.pe.get_data_directory(exe::ImageDirectoryEntry::Security) else {
            return Err(authenticode::PeOffsetError);
        };
        let x: RVA = security_dir.virtual_address;
        let Ok(offset) = x.as_offset(&self.pe) else {
            return Err(authenticode::PeOffsetError);
        };

        let checksum = match arch {
            exe::Arch::X86 => mem::size_of::<exe::ImageOptionalHeader32>() + 64,
            exe::Arch::X64 => mem::size_of::<exe::ImageOptionalHeader64>() + 64,
        };

        Ok(PeOffsets {
            check_sum: checksum,
            after_check_sum: checksum + 4,

            security_data_dir: offset.0 as usize,
            after_security_data_dir: (offset.0 + security_dir.size) as usize,

            after_header: size_of_headers,
        })
    }
}

pub fn display_sig(pe: &VecPE) {
    let security_dir = match pe.get_data_directory(exe::ImageDirectoryEntry::Security) {
        Ok(security_dir) => security_dir,
        Err(_) => {
            println!("No security directory");
            return;
        }
    };
    if security_dir.virtual_address.0 == 0 {
        println!("Not signed");
    } else {
        let peparse = PEForParsing {
            pe : pe.clone()
        };
        let signatures =
            if let Some(iter) = AttributeCertificateIterator::new(&peparse).unwrap() {
                iter.map(|attr_cert| attr_cert.get_authenticode_signature())
                    .collect::<Result<Vec<_>, _>>().unwrap()
            } else {
                println!("No signatures");
                return;
            };

        for (signature_index, s) in signatures.iter().enumerate() {
            println!("Signature {signature_index}:");

            print!("  Digest: ");
            for byte in s.digest() {
                print!("{byte:02x}");
            }
            println!();

            println!("  Signer:");
            if let SignerIdentifier::IssuerAndSerialNumber(sid) =
                &s.signer_info().sid
            {
                println!("    Issuer:        {}", sid.issuer);
                println!("    Serial number: {}", sid.serial_number);
            }

            for (i, cert) in s.certificates().enumerate() {
                println!("  Certificate {i}:");

                println!("    Issuer:        {}", cert.tbs_certificate.issuer);
                println!("    Subject:       {}", cert.tbs_certificate.subject);
                println!(
                    "    Serial number: {}",
                    cert.tbs_certificate.serial_number
                );
            }
        }
    }
}

