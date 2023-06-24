use exe::{Buffer, VecPE, PE};

pub fn display_hashes(pe: &VecPE) {
    let sha256_digest = sha256::digest(pe.get_buffer().as_ref());
    let md5_digest = md5::compute(pe.get_buffer().as_ref());
    println!(
        "{:10}: {}\n{:10}: {}\n{:10}: {}",
        "MD5",
        format!("{:x}", md5_digest),
        "SHA256",
        sha256_digest,
        "Imphash",
        hex::encode(&pe.calculate_imphash().unwrap())
    );
}
