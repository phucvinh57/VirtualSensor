fn main() {
    // Path to lib folder
    println!("cargo:rustc-flags=-L /home/phucvinh//University/Thesis/VirtualSensor/lib");
    println!("cargo:rustc-link-lib=static=pcap");
}
