use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::mem::size_of;
use std::os::windows::{
    ffi::{OsStrExt, OsStringExt},
    fs::{MetadataExt, OpenOptionsExt},
    io::AsRawHandle,
};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use windows_sys::core::GUID;
use windows_sys::Win32::{
    Security::{
        Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE},
        WinTrust::{
            WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
            WTHelperProvDataFromStateData, WinVerifyTrustEx, WINTRUST_ACTION_GENERIC_VERIFY_V2,
            WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
            WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        },
    },
    Storage::FileSystem::{GetDriveTypeW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ},
    System::{
        Com::CoTaskMemFree, SystemInformation::GetWindowsDirectoryW,
        WindowsProgramming::DRIVE_FIXED,
    },
    UI::Shell::{
        FOLDERID_LocalAppData, FOLDERID_ProgramFiles, SHGetKnownFolderPath, KF_FLAG_DEFAULT_PATH,
    },
};

pub(super) fn system_client() -> Option<(PathBuf, File)> {
    let candidate =
        known_folder(&FOLDERID_ProgramFiles)?.join("Docker/Docker/resources/bin/docker.exe");
    if !is_plain_local_path(&candidate) {
        return None;
    }
    // Keep this handle open for the life of the client to deny file writes and replacement.
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&candidate)
        .ok()?;
    (file.metadata().ok()?.is_file() && has_docker_signature(&candidate, &file))
        .then_some((candidate, file))
}

pub(super) fn config_parent() -> Option<PathBuf> {
    let candidate = known_folder(&FOLDERID_LocalAppData)?.join("Temp");
    (is_plain_local_path(&candidate) && candidate.is_dir()).then_some(candidate)
}

pub(super) fn system_root() -> Option<OsString> {
    let mut buffer = [0; 32768];
    // SAFETY: The buffer has the exact capacity supplied to the system function.
    let len = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    (len > 0 && len < buffer.len()).then(|| OsString::from_wide(&buffer[..len]))
}

fn known_folder(id: &GUID) -> Option<PathBuf> {
    let mut path = null_mut();
    // SAFETY: The GUID and output pointer live for the call. The documented allocation
    // belongs to this caller and is released with CoTaskMemFree.
    unsafe {
        let result = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT_PATH as u32, null_mut(), &mut path);
        let value = if result == 0 && !path.is_null() {
            (0..32768).find(|index| *path.add(*index) == 0).map(|len| {
                PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(path, len)))
            })
        } else {
            None
        };
        CoTaskMemFree(path.cast());
        value
    }
}

fn is_plain_local_path(path: &Path) -> bool {
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return false;
    };
    let Prefix::Disk(drive) = prefix.kind() else {
        return false;
    };
    let drive_root = [u16::from(drive), b':' as u16, b'\\' as u16, 0];
    // SAFETY: drive_root is a nul-terminated Windows drive root.
    path.is_absolute()
        && unsafe { GetDriveTypeW(drive_root.as_ptr()) } == DRIVE_FIXED
        && path.ancestors().all(|part| {
            fs::symlink_metadata(part)
                .is_ok_and(|meta| meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0)
        })
}

fn has_docker_signature(path: &Path, file: &File) -> bool {
    let path: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: file.as_raw_handle(),
        ..Default::default()
    };
    let mut trust = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL
            | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            | WTD_DISABLE_MD2_MD4,
        ..Default::default()
    };
    let mut policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: The file handle, path and descriptor live through VERIFY and CLOSE. All
    // provider-owned pointers are checked before use and consumed before CLOSE.
    unsafe {
        let valid =
            WinVerifyTrustEx(null_mut(), &mut policy, &mut trust) == 0 && docker_publisher(&trust);
        trust.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrustEx(null_mut(), &mut policy, &mut trust);
        valid
    }
}

unsafe fn docker_publisher(trust: &WINTRUST_DATA) -> bool {
    let data = unsafe { WTHelperProvDataFromStateData(trust.hWVTStateData) };
    if data.is_null() {
        return false;
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(data, 0, 0, 0) };
    if signer.is_null() {
        return false;
    }
    let Some(certificate) = (unsafe { WTHelperGetProvCertFromChain(signer, 0).as_ref() }) else {
        return false;
    };
    if certificate.pCert.is_null() {
        return false;
    }
    let mut name = [0; 64];
    let len = unsafe {
        CertGetNameStringW(
            certificate.pCert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            null(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } as usize;
    (1..name.len()).contains(&len)
        && matches!(
            String::from_utf16_lossy(&name[..len - 1]).as_str(),
            "Docker Inc" | "Docker Inc."
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_without_a_local_drive_are_rejected() {
        assert!(!is_plain_local_path(Path::new("docker.exe")));
        assert!(!is_plain_local_path(Path::new(
            &[r"\\", "example.invalid", r"\fixture\docker.exe"].concat()
        )));
        assert!(!is_plain_local_path(Path::new(r"C:docker.exe")));
    }
}
