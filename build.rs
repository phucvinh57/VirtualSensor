fn main() {
    // Path to lib folder
    println!("cargo:rustc-link-search=native=./lib");
    println!("cargo:rustc-link-lib=static=pcap");
}
