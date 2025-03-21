use std::borrow::Borrow;
use std::path::PathBuf;
use std::{fs::File, io::Read};

pub fn file_to_packet<T: Borrow<PathBuf>>(fname: T) -> Vec<u8> {
    let mut file = File::open(fname.borrow()).unwrap();
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
