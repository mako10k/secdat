use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::os::raw::c_long;
use std::ptr;
use std::slice;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Locked = 0,
    Environment = 1,
    Session = 2,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveSource {
    Locked = 0,
    Environment = 1,
    LocalSession = 2,
    InheritedSession = 3,
    ExplicitLock = 4,
    Blocked = 5,
}

const PATH_MAX: usize = 4096;

#[repr(C)]
struct RawOptions {
    dir: *const c_char,
    domain: *const c_char,
    store: *const c_char,
}

#[repr(C)]
struct RawStatusSummary {
    store_count: usize,
    visible_key_count: usize,
    wrapped_master_key_present: c_int,
    key_source: c_int,
    effective_source: c_int,
    session_expires_at: c_long,
    related_domain_root: [c_char; PATH_MAX],
}

#[link(name = "secdat")]
extern "C" {
    fn secdat_sdk_get(
        options: *const RawOptions,
        keyref: *const c_char,
        value_out: *mut *mut c_uchar,
        value_length_out: *mut usize,
        unsafe_store_out: *mut c_int,
    ) -> c_int;
    fn secdat_sdk_set(
        options: *const RawOptions,
        keyref: *const c_char,
        value: *const c_uchar,
        value_length: usize,
        unsafe_store: c_int,
    ) -> c_int;
    fn secdat_sdk_rm(options: *const RawOptions, keyref: *const c_char, ignore_missing: c_int) -> c_int;
    fn secdat_sdk_mv(
        options: *const RawOptions,
        source_keyref: *const c_char,
        destination_keyref: *const c_char,
    ) -> c_int;
    fn secdat_sdk_cp(
        options: *const RawOptions,
        source_keyref: *const c_char,
        destination_keyref: *const c_char,
    ) -> c_int;
    fn secdat_sdk_mask(options: *const RawOptions, keyref: *const c_char) -> c_int;
    fn secdat_sdk_unmask(options: *const RawOptions, keyref: *const c_char) -> c_int;
    fn secdat_sdk_unlock(options: *const RawOptions) -> c_int;
    fn secdat_sdk_lock(options: *const RawOptions) -> c_int;
    fn secdat_sdk_exists(
        options: *const RawOptions,
        keyref: *const c_char,
        exists_out: *mut c_int,
    ) -> c_int;
    fn secdat_sdk_collect_status(options: *const RawOptions, summary: *mut RawStatusSummary) -> c_int;
    fn secdat_sdk_free(pointer: *mut c_void);
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub dir: Option<String>,
    pub domain: Option<String>,
    pub store: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StatusSummary {
    pub store_count: usize,
    pub visible_key_count: usize,
    pub wrapped_master_key_present: bool,
    pub key_source: KeySource,
    pub effective_source: EffectiveSource,
    pub session_expires_at: i128,
    pub related_domain_root: String,
}

#[derive(Debug)]
pub struct Error {
    message: &'static str,
}

impl Error {
    fn failed() -> Self {
        Self {
            message: "libsecdat call failed; see stderr for details",
        }
    }

    fn invalid_string() -> Self {
        Self {
            message: "string contains interior NUL byte",
        }
    }

    fn invalid_status_enum() -> Self {
        Self {
            message: "libsecdat returned an unknown status enum value",
        }
    }
}

impl KeySource {
    fn from_raw(value: i32) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Locked),
            1 => Ok(Self::Environment),
            2 => Ok(Self::Session),
            _ => Err(Error::invalid_status_enum()),
        }
    }
}

impl EffectiveSource {
    fn from_raw(value: i32) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Locked),
            1 => Ok(Self::Environment),
            2 => Ok(Self::LocalSession),
            3 => Ok(Self::InheritedSession),
            4 => Ok(Self::ExplicitLock),
            5 => Ok(Self::Blocked),
            _ => Err(Error::invalid_status_enum()),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for Error {}

struct PreparedOptions {
    raw: RawOptions,
    _dir: Option<CString>,
    _domain: Option<CString>,
    _store: Option<CString>,
}

impl PreparedOptions {
    fn new(options: &Options) -> Result<Self, Error> {
        let dir = to_cstring(&options.dir)?;
        let domain = to_cstring(&options.domain)?;
        let store = to_cstring(&options.store)?;
        Ok(Self {
            raw: RawOptions {
                dir: dir.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
                domain: domain.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
                store: store.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
            },
            _dir: dir,
            _domain: domain,
            _store: store,
        })
    }
}

fn to_cstring(value: &Option<String>) -> Result<Option<CString>, Error> {
    match value {
        Some(value) => CString::new(value.as_str()).map(Some).map_err(|_| Error::invalid_string()),
        None => Ok(None),
    }
}

pub fn get(options: &Options, keyref: &str) -> Result<(Vec<u8>, bool), Error> {
    let prepared = PreparedOptions::new(options)?;
    let keyref = CString::new(keyref).map_err(|_| Error::invalid_string())?;
    let mut value = ptr::null_mut();
    let mut value_length = 0usize;
    let mut unsafe_store = 0;

    let status = unsafe {
        secdat_sdk_get(
            &prepared.raw,
            keyref.as_ptr(),
            &mut value,
            &mut value_length,
            &mut unsafe_store,
        )
    };
    if status != 0 {
        return Err(Error::failed());
    }

    let bytes = unsafe { slice::from_raw_parts(value, value_length).to_vec() };
    unsafe {
        secdat_sdk_free(value.cast::<c_void>());
    }
    Ok((bytes, unsafe_store != 0))
}

pub fn set(options: &Options, keyref: &str, value: &[u8], unsafe_store: bool) -> Result<(), Error> {
    let prepared = PreparedOptions::new(options)?;
    let keyref = CString::new(keyref).map_err(|_| Error::invalid_string())?;
    let payload = if value.is_empty() {
        ptr::null()
    } else {
        value.as_ptr()
    };

    let status = unsafe {
        secdat_sdk_set(
            &prepared.raw,
            keyref.as_ptr(),
            payload,
            value.len(),
            i32::from(unsafe_store),
        )
    };
    if status != 0 {
        return Err(Error::failed());
    }
    Ok(())
}

pub fn remove(options: &Options, keyref: &str, ignore_missing: bool) -> Result<(), Error> {
    let prepared = PreparedOptions::new(options)?;
    let keyref = CString::new(keyref).map_err(|_| Error::invalid_string())?;

    let status = unsafe { secdat_sdk_rm(&prepared.raw, keyref.as_ptr(), i32::from(ignore_missing)) };
    if status != 0 {
        return Err(Error::failed());
    }
    Ok(())
}

pub fn mv(options: &Options, source_keyref: &str, destination_keyref: &str) -> Result<(), Error> {
    let prepared = PreparedOptions::new(options)?;
    let source_keyref = CString::new(source_keyref).map_err(|_| Error::invalid_string())?;
    let destination_keyref = CString::new(destination_keyref).map_err(|_| Error::invalid_string())?;

    let status = unsafe { secdat_sdk_mv(&prepared.raw, source_keyref.as_ptr(), destination_keyref.as_ptr()) };
    if status != 0 {
        return Err(Error::failed());
    }
    Ok(())
}

pub fn cp(options: &Options, source_keyref: &str, destination_keyref: &str) -> Result<(), Error> {
    let prepared = PreparedOptions::new(options)?;
    let source_keyref = CString::new(source_keyref).map_err(|_| Error::invalid_string())?;
    let destination_keyref = CString::new(destination_keyref).map_err(|_| Error::invalid_string())?;

    let status = unsafe { secdat_sdk_cp(&prepared.raw, source_keyref.as_ptr(), destination_keyref.as_ptr()) };
    if status != 0 {
        return Err(Error::failed());
    }
    Ok(())
}

pub fn mask(options: &Options, keyref: &str) -> Result<(), Error> {
    let prepared = PreparedOptions::new(options)?;
    let keyref = CString::new(keyref).map_err(|_| Error::invalid_string())?;

    let status = unsafe { secdat_sdk_mask(&prepared.raw, keyref.as_ptr()) };
    if status != 0 {
        return Err(Error::failed());
    }
    Ok(())
}

pub fn unmask(options: &Options, keyref: &str) -> Result<(), Error> {
    let prepared = PreparedOptions::new(options)?;
    let keyref = CString::new(keyref).map_err(|_| Error::invalid_string())?;

    let status = unsafe { secdat_sdk_unmask(&prepared.raw, keyref.as_ptr()) };
    if status != 0 {
        return Err(Error::failed());
    }
    Ok(())
}

pub fn unlock(options: &Options) -> Result<(), Error> {
    let prepared = PreparedOptions::new(options)?;

    let status = unsafe { secdat_sdk_unlock(&prepared.raw) };
    if status != 0 {
        return Err(Error::failed());
    }
    Ok(())
}

pub fn lock(options: &Options) -> Result<(), Error> {
    let prepared = PreparedOptions::new(options)?;

    let status = unsafe { secdat_sdk_lock(&prepared.raw) };
    if status != 0 {
        return Err(Error::failed());
    }
    Ok(())
}

pub fn exists(options: &Options, keyref: &str) -> Result<bool, Error> {
    let prepared = PreparedOptions::new(options)?;
    let keyref = CString::new(keyref).map_err(|_| Error::invalid_string())?;
    let mut exists = 0;

    let status = unsafe { secdat_sdk_exists(&prepared.raw, keyref.as_ptr(), &mut exists) };
    if status != 0 {
        return Err(Error::failed());
    }
    Ok(exists != 0)
}

pub fn collect_status(options: &Options) -> Result<StatusSummary, Error> {
    let prepared = PreparedOptions::new(options)?;
    let mut summary = RawStatusSummary {
        store_count: 0,
        visible_key_count: 0,
        wrapped_master_key_present: 0,
        key_source: 0,
        effective_source: 0,
        session_expires_at: 0,
        related_domain_root: [0; PATH_MAX],
    };

    let status = unsafe { secdat_sdk_collect_status(&prepared.raw, &mut summary) };
    if status != 0 {
        return Err(Error::failed());
    }

    let related_domain_root = unsafe { CStr::from_ptr(summary.related_domain_root.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let key_source = KeySource::from_raw(summary.key_source)?;
    let effective_source = EffectiveSource::from_raw(summary.effective_source)?;

    Ok(StatusSummary {
        store_count: summary.store_count,
        visible_key_count: summary.visible_key_count,
        wrapped_master_key_present: summary.wrapped_master_key_present != 0,
        key_source,
        effective_source,
        session_expires_at: summary.session_expires_at as i128,
        related_domain_root,
    })
}