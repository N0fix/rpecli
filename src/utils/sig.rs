use std::{collections::HashMap, fmt::Display, mem};

use crate::{alert_format, alert_format_if, color_format_if, warn_format, warn_format_if};
use authenticode::{
    AttributeCertificateError, AttributeCertificateIterator, AuthenticodeSignature, PeOffsets,
    PeTrait,
};
use cms::signed_data::SignerIdentifier;
use colored::Colorize;
use exe::{
    pe, Address, ImageDataDirectory, VSFixedFileInfo, VSStringFileInfo, VSStringTable,
    VSVersionInfo, VecPE, WCharString, PE, RVA,
};
use serde::{Deserialize, Serialize};

struct PEForParsing {
    pe: exe::pe::VecPE,
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
        Ok(section.pointer_to_raw_data.0 as usize
            ..(section.size_of_raw_data + section.pointer_to_raw_data.0) as usize)
    }

    fn certificate_table_range(
        &self,
    ) -> Result<Option<std::ops::Range<usize>>, authenticode::PeOffsetError> {
        let security_dir = match self
            .pe
            .get_data_directory(exe::ImageDirectoryEntry::Security)
        {
            Ok(security_dir) => security_dir,
            Err(_) => {
                return Ok(None);
            }
        };
        Ok(Some(
            security_dir.virtual_address.0 as usize
                ..(security_dir.virtual_address.0 + security_dir.size) as usize,
        ))
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

        let Ok(security_dir) = self
            .pe
            .get_data_directory(exe::ImageDirectoryEntry::Security)
        else {
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

#[derive(Serialize, Deserialize, Default, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct Identifier {
    pub issuer: String,
    pub serial_number: String,
}
#[derive(Serialize, Deserialize, Default, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct Cert {
    pub issuer: String,
    pub subject: String,
    pub serial_number: String,
}
#[derive(Serialize, Deserialize, Default, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct AuthenSig {
    // signature_index: u32,
    pub digest: String,
    pub issuer: Option<Identifier>,
    pub certificates: Vec<Cert>,
}
#[derive(Serialize, Deserialize, Default, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct PeAuthenticodes {
    pub signatures: Vec<AuthenSig>,
}

impl PeAuthenticodes {
    pub fn parse(pe: &VecPE) -> Result<PeAuthenticodes, AttributeCertificateError> {
        let mut result = PeAuthenticodes { signatures: vec![] };
        let security_dir = match pe.get_data_directory(exe::ImageDirectoryEntry::Security) {
            Ok(security_dir) => security_dir,
            Err(_) => return Ok(result),
        };
        if security_dir.virtual_address.0 == 0 {
            return Ok(result);
        } else {
            let peparse = PEForParsing { pe: pe.clone() };
            let sig_iterator = AttributeCertificateIterator::new(&peparse)?;
            if let Some(sigs) = sig_iterator {
                for (sig_id, sig) in sigs.enumerate() {
                    match sig {
                        Ok(s) => {
                            if s.get_authenticode_signature().is_ok() {
                                result
                                    .signatures
                                    .push(AuthenSig::from(s.get_authenticode_signature().unwrap()))
                            }
                        }
                        Err(e) => {
                            match e {
                                AttributeCertificateError::InvalidCertificateSize { size } => {
                                    return Err(AttributeCertificateError::InvalidCertificateSize {
                                        size: sig_id as u32 + 1,
                                    })
                                }
                                _ => {}
                            };
                            return Err(e);
                        }
                    };
                }
            }
        }

        Ok(result)
    }
}

impl From<AuthenticodeSignature> for AuthenSig {
    fn from(value: AuthenticodeSignature) -> Self {
        let mut identifier: Option<Identifier> = None;
        if let SignerIdentifier::IssuerAndSerialNumber(sid) = &value.signer_info().sid {
            identifier = Some(Identifier {
                issuer: sid.issuer.to_string(),
                serial_number: sid.serial_number.to_string(),
            });
        }
        let mut certs = vec![];
        for cert in value.certificates() {
            certs.push(Cert {
                issuer: cert.tbs_certificate.issuer.to_string(),
                subject: cert.tbs_certificate.subject.to_string(),
                serial_number: cert.tbs_certificate.serial_number.to_string(),
            });
        }
        AuthenSig {
            digest: hex::encode(&value.digest()),
            issuer: identifier,
            certificates: certs,
        }
    }
}

impl Display for PeAuthenticodes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.signatures.len() == 0 {
            return writeln!(f, "{}", warn_format!("PE file is not signed"));
        }

        for (signature_index, s) in self.signatures.iter().enumerate() {
            writeln!(f, "Entry {signature_index}:")?;

            write!(f, "  Signature digest: ")?;
            // for byte in &s.digest {
            //     write!(f, "{byte:02x}")?;
            // }
            writeln!(f, "{}\n", &s.digest)?;

            writeln!(f, "  Signer:")?;
            if let Some(sid) = &s.issuer {
                writeln!(f, "    Issuer:        {}", sid.issuer)?;
                writeln!(f, "    Serial number: {}", sid.serial_number)?;
            }

            for (i, cert) in s.certificates.iter().enumerate() {
                writeln!(f, "  Certificate {i}:")?;

                writeln!(f, "    Issuer:        {}", cert.issuer)?;
                writeln!(f, "    Subject:       {}", cert.subject)?;
                writeln!(f, "    Serial number: {}", cert.serial_number)?;
            }
        }
        writeln!(f, "")
    }
}

pub fn display_sig(pe: &VecPE) {
    let sigs = match PeAuthenticodes::parse(pe) {
        Ok(sigs) => sigs,
        Err(e) => match e {
            AttributeCertificateError::OutOfBounds => {
                println!(
                    "{}",
                    alert_format!("Security directory exists, but is out of bounds")
                );
                return;
            }
            AttributeCertificateError::InvalidSize => {
                println!(
                    "{}",
                    alert_format!("Security directory exists, but signature has an invalid size")
                );
                return;
            }
            AttributeCertificateError::InvalidCertificateSize { size } => {
                println!(
                    "{}",
                    alert_format!(format!("Signature {} has an invalid size", size))
                );
                return;
            }
        },
    };
    println!("{}", sigs);
}
