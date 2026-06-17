fn main() {
    pkg_config::Config::new()
        .atleast_version("0.2.1")
        .probe("libsecdat")
        .expect("pkg-config could not find libsecdat");
}
