use crate::utils::sections::get_section_name_from_offset;
use exe::{ImageTLSDirectory32, ImageTLSDirectory64, VecPE, PE};

pub fn display_tls<P: PE>(pe: &P) {
    match pe.get_arch().unwrap() {
        exe::Arch::X86 => {
            let tls = ImageTLSDirectory32::parse(pe);
            if tls.is_err() {
                println!("No TLS callback directory");
                return;
            }
            let callbacks = tls.unwrap().get_callbacks(pe).unwrap();
            if callbacks.len() == 0 {
                println!("TLS callback table exists but is empty");
                return;
            }
            for callback in callbacks {
                match get_section_name_from_offset(callback.0 as u64, pe) {
                    Ok(s) => println!("{:x} => {}", callback.0, s),
                    Err(_) => {
                        println!("{:x} => Not in a section", callback.0)
                    }
                }
            }
        }
        exe::Arch::X64 => {
            let tls = ImageTLSDirectory64::parse(pe);
            if tls.is_err() {
                println!("No TLS callback directory");
                return;
            }
            let callbacks = tls.unwrap().get_callbacks(pe).unwrap();
            if callbacks.len() == 0 {
                println!("TLS callback table exists but is empty");
                return;
            }
            for callback in callbacks {
                match get_section_name_from_offset(callback.0 as u64, pe) {
                    Ok(s) => println!("{:x} => {}", callback.0, s),
                    Err(_) => {
                        println!("{:x} => Not in a section", callback.0)
                    }
                }
            }
        }
    };
}
