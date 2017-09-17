#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate libc;
extern crate openssl;
extern crate toml;
extern crate uuid;

pub mod bindings;
pub mod auth;

use bindings::*;

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_setcred(
    pamh: *mut pam_handle_t,
    flags: ::std::os::raw::c_int,
    argc: ::std::os::raw::c_int,
    argv: *mut *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    PAM_IGNORE
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_acct_mgmt(
    pamh: *mut pam_handle_t,
    flags: ::std::os::raw::c_int,
    argc: ::std::os::raw::c_int,
    argv: *mut *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    PAM_IGNORE
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_open_session(
    pamh: *mut pam_handle_t,
    flags: ::std::os::raw::c_int,
    argc: ::std::os::raw::c_int,
    argv: *mut *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    PAM_IGNORE
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_close_session(
    pamh: *mut pam_handle_t,
    flags: ::std::os::raw::c_int,
    argc: ::std::os::raw::c_int,
    argv: *mut *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    PAM_IGNORE
}

#[no_mangle]
#[allow(unused_variables)]
pub fn pam_sm_chauthtok(
    pamh: *mut pam_handle_t,
    flags: ::std::os::raw::c_int,
    argc: ::std::os::raw::c_int,
    argv: *mut *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    PAM_IGNORE
}
