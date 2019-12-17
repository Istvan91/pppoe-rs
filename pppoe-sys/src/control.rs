#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
include!(concat!(env!("OUT_DIR"), "/control_bindings.rs"));

use std::io;

pub fn init() -> io::Result<()> {
    let ret = unsafe { control_socket_init() };
    if ret < 0 {
        return Err(io::Error::from_raw_os_error(ret));
    }

    Ok(())
}
