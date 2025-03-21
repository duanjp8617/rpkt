mod common;
use common::file_to_packet;

#[test]
fn fuck() {
    // The test is executed under the crate root directory.
    let mut program_path = std::env::current_dir().unwrap();
    program_path.push("tests");
    program_path.push("packet_examples");
    program_path.push("ArpResponsePacket.dat");
    let res = file_to_packet(&program_path);

    for c in res.iter() {
        print!("{:02x}", c);
    }
    println!();
}
