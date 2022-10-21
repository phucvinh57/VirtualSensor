fn main() {
    println!("cargo:rustc-flags=-L /home/yoru/G/Thesis/Source/MonitorDaemon/lib");
    println!("cargo:rustc-link-lib=static=pcap");
}
