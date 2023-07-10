use crate::utils::sections::get_section_name_from_offset;
use colored::Colorize;
use exe::{Address, ImageTLSDirectory32, ImageTLSDirectory64, VecPE, PE};

struct TLSCallbacks {
    callbacks: Vec<u64>
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
        let matching_section_name = match get_section_name_from_offset(callback_va, pe) {
            Some(s) => s,
            None => String::from("Not in a section"),
        };
        println!("\t{} => {}", callback_va, matching_section_name);
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
