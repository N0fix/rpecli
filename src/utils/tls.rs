use std::fmt::Display;

use crate::utils::sections::get_section_name_from_offset;
use colored::Colorize;
use exe::{Address, ImageDirectoryEntry, ImageTLSDirectory32, ImageTLSDirectory64, PETranslation, VecPE, PE, RVA};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct TLSCallbacks {
    pub callbacks: Vec<u64>,
}

impl TLSCallbacks {
    pub fn check_exists(pe: &VecPE) -> bool {
        if let Ok(security_dir) = pe
            .get_data_directory(exe::ImageDirectoryEntry::TLS){
                if security_dir.virtual_address.0 != 0 {
                    return true;
                }
            }
        return false;
    }

    pub fn parse(pe: &VecPE) -> Result<Option<TLSCallbacks>, exe::Error> {
        if !pe.has_data_directory(ImageDirectoryEntry::TLS) {
            return Ok(None);
        }

        let tls_callbacks = match pe.get_arch()? {
            exe::Arch::X86 => {
                let tls = ImageTLSDirectory32::parse(pe)?;
                let callbacks = tls.get_callbacks(pe)?;
                handle_callbacks(callbacks, pe)
            }
            exe::Arch::X64 => {
                let tls = ImageTLSDirectory64::parse(pe)?;
                let callbacks = tls.get_callbacks(pe)?;
                handle_callbacks(callbacks, pe)
            }
        };
        Ok(Some(TLSCallbacks {
            callbacks: tls_callbacks,
        }))
    }
}

impl Display for TLSCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for tls in &self.callbacks {
            writeln!(f, "{:#x}", tls)?;
        }
        Ok(())
    }
}


fn handle_callbacks<A: Address>(callbacks: &[A], pe: &VecPE) -> Vec<u64> {
    let mut result = vec![];

    if callbacks.len() == 0 {
        return result;
    }
    for callback in callbacks {
        let callback_va: u64 = match callback.as_va(pe).unwrap() {
            exe::VA::VA32(val) => val.0.into(),
            exe::VA::VA64(val) => val.0,
        };
        result.push(callback_va);
    }

    result
}
