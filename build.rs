fn main() {
    // Path to lib folder
    // println!("cargo:rustc-flags=-L /home/phucvinh/Thesis/Source/MonitorDaemon/lib");
    println!("cargo:rustc-link-lib=static=pcap");
}
