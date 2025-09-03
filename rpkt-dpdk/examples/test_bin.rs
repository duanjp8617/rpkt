fn main() {
    println!("{}", std::thread::available_parallelism().unwrap());
}