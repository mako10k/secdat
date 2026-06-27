fn main() {
    pkg_config::Config::new()
        .atleast_version("0.4.0")
        .probe("libsecdat")
        .expect("pkg-config could not find libsecdat");
}
