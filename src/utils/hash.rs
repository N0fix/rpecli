use exe::{Buffer, HashData, VecPE, PE};

pub fn display_hashes(pe: &VecPE) {
    // let sha256_digest = sha256::digest(pe.get_buffer().as_ref());
    // let md5_digest = md5::compute(pe.get_buffer().as_ref());
    println!("{:10}: {}", "MD5", hex::encode(&pe.md5()));
    println!("{:10}: {}", "SHA1", hex::encode(&pe.sha1()));
    println!("{:10}: {}", "SHA256", hex::encode(&pe.sha256()));
}
