use std::env;
use std::path::PathBuf;

fn main() {
    cc::Build::new().file("pppoe/pppoe.c").compile("pppoe");

    for header in &["pppoe", "control"] {
        let bindings = bindgen::Builder::default()
            .header(&format!("pppoe/{}.h", header))
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("Unable to generate bindings");

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

        bindings
            .write_to_file(out_path.join(&format!("{}_bindings.rs", header)))
            .expect("Couldn't write bindings");
    }
}
