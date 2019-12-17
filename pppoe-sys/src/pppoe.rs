#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
mod internal {
    include!(concat!(env!("OUT_DIR"), "/pppoe_bindings.rs"));
}

use std::ffi::CString;
use std::num::NonZeroU16;
use std::os::unix::io::RawFd;
use std::{io, mem, ptr};

#[derive(Debug)]
#[repr(transparent)]
pub struct Connection(internal::PppoeConnectionData);

impl Connection {
    pub fn new() -> Self {
        let data = mem::MaybeUninit::<internal::PppoeConnectionData>::zeroed();
        Self(unsafe { data.assume_init() })
    }

    pub fn set_interface_name(&mut self, interface_name: &str) -> io::Result<()> {
        if interface_name.len() > self.0.interface_name.len() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Interface name too long",
            ));
        }

        self.0.interface_name[..interface_name.len()]
            .copy_from_slice(unsafe { &*(interface_name.as_bytes() as *const _ as *const [i8]) });
        get_hardware_address(self)?;
        Ok(())
    }

    pub fn raw_socket(&self) -> RawFd {
        self.0.raw_socket
    }

    pub fn pppoe_socket(&self) -> RawFd {
        self.0.pppoe_socket
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.0.mac_address
    }
}

pub fn connection_data_init(
    connection: &mut Connection,
    interface_name: Option<String>,
) -> io::Result<()> {
    let interface_name = match interface_name {
        Some(interface_name) => CString::new(interface_name).unwrap().as_ptr(),
        None => ptr::null(),
    };

    let ret = unsafe {
        internal::pppoe_connection_data_init(&mut connection.0 as *mut _, interface_name)
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub fn connect(connection: &mut Connection, session_id: NonZeroU16) -> io::Result<()> {
    let ret =
        unsafe { internal::pppoe_connect(&mut connection.0 as *mut _, u16::from(session_id)) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub fn connection_data_clear(connection: &mut Connection) {
    unsafe {
        internal::pppoe_connection_data_clear(&mut connection.0 as *mut _);
    }
}

fn get_hardware_address(connection: &mut Connection) -> io::Result<()> {
    let ret = unsafe { internal::lookup_hardware_address(&mut connection.0 as *mut _) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            internal::pppoe_connection_data_clear(&mut self.0 as *mut _);
        }
    }
}
