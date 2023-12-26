use crate::utils::sections::get_section_name_from_offset;
use colored::Colorize;
use exe::{Address, ImageTLSDirectory32, ImageTLSDirectory64, PETranslation, VecPE, PE, RVA};

struct TLSCallbacks {
    callbacks: Vec<u64>,
}
//wip
// impl TLSCallbacks {
//     pub fn parse_pe(pe: &VecPE) -> Option<TLSCallbacks> {
//         match pe.get_arch().unwrap() {
//             exe::Arch::X86 => {
//                 let Ok(tls) = ImageTLSDirectory32::parse(pe) else {
//                     return None;
//                 };
//                 let Ok(callbacks) = tls.get_callbacks(pe) else {
//                     println!("{}", "Invalid callbacks".red());
//                     return;
//                 };
//                 handle_callbacks(callbacks, pe);
//             }
//             exe::Arch::X64 => {
//                 let Ok(tls) = ImageTLSDirectory64::parse(pe) else {
//                     println!("No TLS callback directory");
//                     return;
//                 };
//                 let Ok(callbacks) = tls.get_callbacks(pe) else {
//                     println!("{}", "Invalid callbacks".red());
//                     return;
//                 };
//                 handle_callbacks(callbacks, pe);
//             }
//         };
//     }
// }

fn handle_callbacks<A: Address>(callbacks: &[A], pe: &VecPE) {
    if callbacks.len() == 0 {
        println!("TLS callback table exists but is empty");
        return;
    }
    for callback in callbacks {
        let callback_va: u64 = match callback.as_va(pe).unwrap() {
            exe::VA::VA32(val) => val.0.into(),
            exe::VA::VA64(val) => val.0,
        };
        print!("\t{:#x}", callback_va);
        if let Ok(cb_rva) = callback.as_rva(pe) {
            let s = match get_section_name_from_offset(cb_rva.0 as u64, pe) {
                Some(s) => print!(" => {}", s),
                None => print!(" => Not in a section"),
            };
        }
        // if let Ok(addr) = pe.translate(PETranslation::Memory(RVA { 0: callback_va as u32 })) {

        // print!("{}", s);
        // }
        println!("");
    }
}

pub fn display_tls(pe: &VecPE) {
    match pe.get_arch().unwrap() {
        exe::Arch::X86 => {
            let Ok(tls) = ImageTLSDirectory32::parse(pe) else {
                println!("No TLS callback directory");
                return;
            };
            let Ok(callbacks) = tls.get_callbacks(pe) else {
                println!("{}", "Invalid callbacks".red());
                return;
            };
            handle_callbacks(callbacks, pe);
        }
        exe::Arch::X64 => {
            let Ok(tls) = ImageTLSDirectory64::parse(pe) else {
                println!("No TLS callback directory");
                return;
            };
            let Ok(callbacks) = tls.get_callbacks(pe) else {
                println!("{}", "Invalid callbacks".red());
                return;
            };
            handle_callbacks(callbacks, pe);
        }
    };
}
