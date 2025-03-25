use std::{fs::File, io::Read};

pub fn file_to_packet(fname: &str) -> Vec<u8> {
    // The test is executed under the crate root directory.
    let mut program_path = std::env::current_dir().unwrap();
    program_path.push("tests");
    program_path.push("packet_examples");
    program_path.push(fname);

    let mut file = File::open(program_path).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    let content = content.trim();

    let mut res = Vec::new();
    let mut start_idx = 0;
    let mut chars = content.chars();
    while chars.as_str().len() > 0 {
        // Pop two characters out
        chars.next();
        chars.next();

        let end_idx = content.len() - chars.as_str().len();
        res.push(u8::from_str_radix(&content[start_idx..end_idx], 16).unwrap());
        start_idx = end_idx;
    }

    res
}

#[allow(dead_code)]
pub fn to_hex_dump(fname: &str) {
    // The test is executed under the crate root directory.
    let mut program_path = std::env::current_dir().unwrap();
    program_path.push("tests");
    program_path.push("packet_examples");
    program_path.push(fname);

    let mut file = File::open(program_path).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    let content = content.trim();

    print!("00000000 ");
    let mut i = 0;
    while i < content.len() {
        print!("{} ", &content[i..i + 2]);
        i += 2;
    }
}
