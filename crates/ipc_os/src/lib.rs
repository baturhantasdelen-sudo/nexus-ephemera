//! Peer identity for the broker daemon.
//!
//! Unsafe is limited to the credential syscalls. The main crate stays
//! `forbid(unsafe_code)`.

#![allow(unsafe_code)]

#[cfg(unix)]
use std::io;

#[cfg(unix)]
pub fn current_uid() -> io::Result<u32> {
    let uid = u64::from(unsafe { libc::getuid() });
    u32::try_from(uid).map_err(|_| io::Error::other("uid does not fit u32"))
}

/// Exclusive PID lock for a daemon listen socket.
///
/// The lock file is `<socket>.lock`. `flock` provides mutual exclusion. Drop
/// releases that advisory lock but never unlinks the path, so another process
/// cannot lose its lock file during shutdown races.
#[cfg(unix)]
pub struct ListenLock {
    file: std::fs::File,
}

#[cfg(unix)]
impl ListenLock {
    pub fn acquire(path: &std::path::Path) -> io::Result<Self> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "lock path contains NUL"))?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a new descriptor from `open`.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        if meta.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "listen lock must have exactly one hard link",
            ));
        }
        if !meta.file_type().is_file() {
            return Err(io::Error::other("listen lock path is not a regular file"));
        }
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "listen lock is not owned by this uid",
            ));
        }
        if meta.mode() & 0o777 != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "listen lock path must be mode 0600",
            ));
        }
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { file })
    }

    pub fn record_pid(&mut self) -> io::Result<()> {
        use std::io::{Seek, Write};
        self.file.set_len(0)?;
        self.file.seek(std::io::SeekFrom::Start(0))?;
        let pid = std::process::id().to_string();
        self.file.write_all(pid.as_bytes())?;
        self.file.flush()?;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for ListenLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Read at most `max` bytes from stdin, or stop at EOF or `timeout`.
///
/// The working buffer is wiped before an error returns. A blocked poll is
/// bounded by the deadline, so the caller can join the reader thread.
#[cfg(unix)]
pub fn read_stdin_bounded(max: usize, timeout: std::time::Duration) -> io::Result<Vec<u8>> {
    read_stdin_bounded_inner(max, timeout, None)
}

/// Like [`read_stdin_bounded`], but returns `TimedOut` as soon as `cancel` is set.
#[cfg(unix)]
pub fn read_stdin_bounded_with_cancel(
    max: usize,
    timeout: std::time::Duration,
    cancel: &std::sync::atomic::AtomicBool,
) -> io::Result<Vec<u8>> {
    read_stdin_bounded_inner(max, timeout, Some(cancel))
}

#[cfg(unix)]
fn read_stdin_bounded_inner(
    max: usize,
    timeout: std::time::Duration,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> io::Result<Vec<u8>> {
    use std::sync::atomic::Ordering;
    if timeout.is_zero() || max == 0 {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "stdin read deadline already passed",
        ));
    }
    let mut buffer = vec![0u8; max];
    let mut filled = 0usize;
    let deadline = std::time::Instant::now() + timeout;
    let result = (|| {
        while filled < max {
            if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stdin read cancelled",
                ));
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stdin read deadline already passed",
                ));
            }
            let wait_ms = i32::try_from(remaining.as_millis().min(10))
                .unwrap_or(10)
                .max(1);
            let mut poll_fd = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut poll_fd, 1, wait_ms) };
            if rc == 0 {
                continue;
            }
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            let n = unsafe {
                libc::read(
                    libc::STDIN_FILENO,
                    buffer[filled..].as_mut_ptr().cast(),
                    max - filled,
                )
            };
            if n == 0 {
                break;
            }
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            filled += usize::try_from(n).map_err(|_| io::Error::other("stdin read overflow"))?;
        }
        Ok(filled)
    })();
    match result {
        Ok(filled) => {
            buffer.truncate(filled);
            Ok(buffer)
        }
        Err(err) => {
            wipe_bytes(&mut buffer);
            Err(err)
        }
    }
}

#[cfg(unix)]
fn wipe_bytes(buffer: &mut [u8]) {
    for byte in buffer {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    #[test]
    fn current_uid_is_readable() {
        assert!(super::current_uid().is_ok());
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::io;

    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        GetSecurityInfo, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, EqualSid, GROUP_SECURITY_INFORMATION,
        GetAce, GetTokenInformation, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    };

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn ReadFile(
            h_file: HANDLE,
            lp_buffer: *mut c_void,
            n_number_of_bytes_to_read: u32,
            lp_number_of_bytes_read: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
    }
    use windows_sys::Win32::System::Pipes::{
        GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThreadId, OpenProcess, OpenProcessToken, OpenThread,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// Specific pipe rights granted in the DACL. The ACE stores these bits, not
    /// unmapped `GENERIC_*`, because client access checks use file mapping.
    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
    /// Same bit as `FILE_FLAG_FIRST_PIPE_INSTANCE`. The first `CreateNamedPipe`
    /// therefore requests this right, and returns error 5 if the ACE omits it.
    const WRITE_OWNER: u32 = 0x0008_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    /// Lets this user create the next instance. Without it the second create
    /// is also error 5.
    const FILE_CREATE_PIPE_INSTANCE: u32 = 0x4;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACL_REVISION: u32 = 2;
    const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 1;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn InitializeAcl(pacl: *mut ACL, n_acl_length: u32, dw_acl_revision: u32) -> i32;
        fn AddAccessAllowedAce(
            pacl: *mut ACL,
            dw_ace_revision: u32,
            access_mask: u32,
            psid: PSID,
        ) -> i32;
        fn GetLengthSid(sid: PSID) -> u32;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PipePeer {
        pub pid: u32,
        pub same_user: bool,
    }

    pub fn pipe_peer(handle: isize) -> io::Result<PipePeer> {
        let mut pid = 0u32;
        let ok = unsafe { GetNamedPipeClientProcessId(handle as HANDLE, &mut pid) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            return Ok(PipePeer {
                pid,
                same_user: false,
            });
        }
        let same_user = same_user_as_current(pid)?;
        Ok(PipePeer { pid, same_user })
    }

    /// Server identity as seen from a connected client handle.
    pub fn pipe_server_peer(handle: isize) -> io::Result<PipePeer> {
        let mut pid = 0u32;
        let ok = unsafe { GetNamedPipeServerProcessId(handle as HANDLE, &mut pid) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            return Ok(PipePeer {
                pid,
                same_user: false,
            });
        }
        let same_user = same_user_as_current(pid)?;
        Ok(PipePeer { pid, same_user })
    }

    /// Apply the exact current-user and optional current-package DACL.
    ///
    /// The ACE trustee is the `TokenUser` SID from `OpenProcessToken` on the
    /// current process, not a static well-known SID. Remote clients are a
    /// AppContainer processes also require their exact package SID. Remote
    /// rejection uses `PIPE_REJECT_REMOTE_CLIENTS` on create. A privileged
    /// administrator can still open the process. This is not mTLS.
    pub fn assert_pipe_dacl_is_current_user_only(handle: isize) -> io::Result<()> {
        let handle = handle as HANDLE;
        dacl_is_current_user_only(handle, SE_KERNEL_OBJECT)
            .or_else(|_| dacl_is_current_user_only(handle, SE_FILE_OBJECT))
    }

    pub fn lock_pipe_to_current_user(handle: isize) -> io::Result<()> {
        let (sid, user, token) = current_process_user_sid()?;
        let _keepalive = (user, token);
        let mut acl = user_only_acl(sid)?;
        let info = OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | PROTECTED_DACL_SECURITY_INFORMATION;
        for object_type in [SE_KERNEL_OBJECT, SE_FILE_OBJECT] {
            let status = unsafe {
                SetSecurityInfo(
                    handle as HANDLE,
                    object_type,
                    info,
                    sid,
                    sid,
                    acl.as_mut_ptr(),
                    ptr::null(),
                )
            };
            if status == ERROR_SUCCESS
                && dacl_is_current_user_only(handle as HANDLE, object_type).is_ok()
            {
                return Ok(());
            }
        }
        Err(io::Error::other("pipe owner dacl was not applied"))
    }

    /// Create with the restrictive descriptor already installed. No interval
    /// exists where the first instance uses the inherited default DACL.
    /// Requires a Tokio I/O runtime, just like ServerOptions::create.
    pub fn create_user_only_pipe(
        name: &str,
        first: bool,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        use windows_sys::Win32::Security::{
            InitializeSecurityDescriptor, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
            SetSecurityDescriptorDacl, SetSecurityDescriptorGroup, SetSecurityDescriptorOwner,
            SetSecurityDescriptorSacl,
        };
        let (sid, _storage, _token) = current_process_user_sid()?;
        let mut acl = user_only_acl(sid)?;
        let mut sacl = process_integrity_sacl()?;
        // SAFETY: all-zero storage is only passed to InitializeSecurityDescriptor;
        // no fields are read before successful initialization.
        let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let ptr = std::ptr::from_mut(&mut descriptor).cast();
        // SAFETY: descriptor, ACL, SID backing storage and attributes remain live
        // for the synchronous create call. Handles are not inherited.
        unsafe {
            if InitializeSecurityDescriptor(ptr, 1) == 0
                || SetSecurityDescriptorOwner(ptr, sid, 0) == 0
                || SetSecurityDescriptorGroup(ptr, sid, 0) == 0
                || SetSecurityDescriptorDacl(ptr, 1, acl.as_mut_ptr(), 0) == 0
                || SetSecurityDescriptorSacl(ptr, 1, sacl.as_mut_ptr(), 0) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr,
            bInheritHandle: 0,
        };
        let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
        options
            .reject_remote_clients(true)
            .first_pipe_instance(first);
        if first {
            // FIRST_PIPE_INSTANCE shares its bit with WRITE_OWNER. Request both
            // owner and DACL rights explicitly so the opened handle can carry them.
            options.write_dac(true).write_owner(true);
        }
        let server = unsafe {
            options.create_with_security_attributes_raw(
                name,
                std::ptr::from_mut(&mut attributes).cast(),
            )
        }?;
        use std::os::windows::io::AsRawHandle;
        assert_pipe_dacl_is_current_user_only(server.as_raw_handle() as isize)?;
        assert_pipe_integrity_matches_process(server.as_raw_handle() as HANDLE)?;
        Ok(server)
    }

    const SYNCHRONIZE: u32 = 0x0010_0000;

    fn client_access_mask() -> u32 {
        FILE_GENERIC_READ
            | FILE_GENERIC_WRITE
            | SYNCHRONIZE
            | WRITE_DAC
            | WRITE_OWNER
            | FILE_CREATE_PIPE_INSTANCE
    }

    /// Explicitly preserve the creator's integrity level. An absolute descriptor
    /// with no mandatory label is treated as medium, even in a low-IL process.
    /// Never lower a medium/high service's label to accommodate a low client.
    fn process_integrity_sacl() -> io::Result<HeapAcl> {
        use windows_sys::Win32::Security::{
            AddMandatoryAce, TOKEN_MANDATORY_LABEL, TokenIntegrityLevel,
        };
        let token = open_token(unsafe { GetCurrentProcess() })?;
        let storage = token_info_bytes(token.0, TokenIntegrityLevel)?;
        // SAFETY: successful TokenIntegrityLevel query returns this structure;
        // aligned storage remains live until AddMandatoryAce copies its SID.
        let sid = unsafe {
            (*storage.as_ptr().cast::<TOKEN_MANDATORY_LABEL>())
                .Label
                .Sid
        };
        let bytes = std::mem::size_of::<ACL>() + 8 + unsafe { GetLengthSid(sid) } as usize;
        let mut acl = HeapAcl(vec![0u32; bytes.div_ceil(4)]);
        unsafe {
            if InitializeAcl(acl.as_mut_ptr(), bytes as u32, ACL_REVISION) == 0
                || AddMandatoryAce(
                    acl.as_mut_ptr(),
                    ACL_REVISION,
                    0,
                    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                    sid,
                ) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(acl)
    }

    fn assert_pipe_integrity_matches_process(handle: HANDLE) -> io::Result<()> {
        use windows_sys::Win32::Security::{
            LABEL_SECURITY_INFORMATION, SYSTEM_MANDATORY_LABEL_ACE,
        };
        let mut sacl = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sacl,
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let _descriptor = LocalAlloc(descriptor);
        if sacl.is_null() || unsafe { (*sacl).AceCount } != 1 {
            return Err(io::Error::other("pipe mandatory label missing"));
        }
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(sacl, 0, &mut ace) } == 0 || ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        let actual = unsafe { &*ace.cast::<SYSTEM_MANDATORY_LABEL_ACE>() };
        if actual.Header.AceType != 0x11 || actual.Mask != SYSTEM_MANDATORY_LABEL_NO_WRITE_UP {
            return Err(io::Error::other("unexpected pipe integrity policy"));
        }
        let mut expected = process_integrity_sacl()?;
        let mut expected_ace = ptr::null_mut();
        if unsafe { GetAce(expected.as_mut_ptr(), 0, &mut expected_ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both ACLs are system-validated and have a mandatory label ACE.
        let equal = unsafe {
            EqualSid(
                ace.byte_add(std::mem::offset_of!(SYSTEM_MANDATORY_LABEL_ACE, SidStart))
                    .cast(),
                expected_ace
                    .byte_add(std::mem::offset_of!(SYSTEM_MANDATORY_LABEL_ACE, SidStart))
                    .cast(),
            )
        };
        if equal == 0 {
            return Err(io::Error::other("pipe and process integrity levels differ"));
        }
        Ok(())
    }

    struct HeapAcl(Vec<u32>);

    impl HeapAcl {
        fn as_mut_ptr(&mut self) -> *mut ACL {
            self.0.as_mut_ptr().cast()
        }
    }

    /// Package identity is a second access-check principal for AppContainers.
    /// Admit only this process's package, never ALL APPLICATION PACKAGES.
    fn process_appcontainer_storage() -> io::Result<Option<Vec<u64>>> {
        use windows_sys::Win32::Security::{TokenAppContainerSid, TokenIsAppContainer};
        let token = open_token(unsafe { GetCurrentProcess() })?;
        let flag = token_info_bytes(token.0, TokenIsAppContainer)?;
        if unsafe { *flag.as_ptr().cast::<u32>() } == 0 {
            return Ok(None);
        }
        let storage = token_info_bytes(token.0, TokenAppContainerSid)?;
        if appcontainer_sid(&storage).is_null() {
            return Err(io::Error::other("AppContainer SID missing"));
        }
        Ok(Some(storage))
    }

    fn appcontainer_sid(storage: &[u64]) -> PSID {
        // SAFETY: callers supply a successful, aligned TokenAppContainerSid query.
        unsafe {
            (*storage
                .as_ptr()
                .cast::<windows_sys::Win32::Security::TOKEN_APPCONTAINER_INFORMATION>())
            .TokenAppContainer
        }
    }

    fn user_only_acl(sid: PSID) -> io::Result<HeapAcl> {
        let package = process_appcontainer_storage()?;
        let mut trustees = vec![sid];
        if let Some(storage) = &package {
            trustees.push(appcontainer_sid(storage));
        }
        let acl_size = std::mem::size_of::<ACL>()
            + trustees
                .iter()
                .map(|sid| 8 + unsafe { GetLengthSid(*sid) } as usize)
                .sum::<usize>();
        let mut acl = HeapAcl(vec![0u32; acl_size.div_ceil(4)]);
        // SAFETY: aligned ACL storage is sized for each validated token SID;
        // AddAccessAllowedAce copies the SIDs while backing storage is live.
        unsafe {
            if InitializeAcl(acl.as_mut_ptr(), acl_size as u32, ACL_REVISION) == 0 {
                return Err(io::Error::last_os_error());
            }
            for trustee in trustees {
                if AddAccessAllowedAce(
                    acl.as_mut_ptr(),
                    ACL_REVISION,
                    client_access_mask(),
                    trustee,
                ) == 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(acl)
    }

    fn dacl_is_current_user_only(handle: HANDLE, object_type: SE_OBJECT_TYPE) -> io::Result<()> {
        let mut owner: PSID = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                object_type,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let _descriptor = LocalAlloc(descriptor);
        if owner.is_null() || dacl.is_null() {
            return Err(io::Error::other(
                "pipe security descriptor is missing an owner or dacl",
            ));
        }
        let (current_sid, user, token) = current_process_user_sid()?;
        let _keepalive = (user, token);
        let owner_match = unsafe { EqualSid(owner, current_sid) };
        if owner_match == 0 {
            return Err(io::Error::other("pipe owner is not the current user"));
        }
        let package = process_appcontainer_storage()?;
        let mut trustees = vec![current_sid];
        if let Some(storage) = &package {
            trustees.push(appcontainer_sid(storage));
        }
        if unsafe { (*dacl).AceCount } as usize != trustees.len() {
            return Err(io::Error::other("unexpected pipe DACL trustees"));
        }
        for (index, expected_sid) in trustees.into_iter().enumerate() {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 || ace.is_null() {
                return Err(io::Error::other("pipe ACE unreadable"));
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            if allowed.Header.AceType != ACCESS_ALLOWED_ACE_TYPE
                || allowed.Header.AceFlags != 0
                || allowed.Mask != client_access_mask()
            {
                return Err(io::Error::other("unexpected pipe ACE rights"));
            }
            let sid = unsafe {
                ace.byte_add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                    .cast()
            };
            if unsafe { EqualSid(sid, expected_sid) } == 0 {
                return Err(io::Error::other("unexpected pipe ACE identity"));
            }
        }
        Ok(())
    }

    /// User SID from the current process token. The returned `Vec` must stay alive
    /// for as long as `sid` is used.
    fn current_process_user_sid() -> io::Result<(PSID, Vec<u64>, Owned)> {
        let token = open_token(unsafe { GetCurrentProcess() })?;
        let user = token_user_bytes(token.0)?;
        let sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        if sid.is_null() {
            return Err(io::Error::other("current user sid missing"));
        }
        Ok((sid, user, token))
    }

    fn same_user_as_current(pid: u32) -> io::Result<bool> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let process = Owned(process);
        let client = open_token(process.0)?;
        // `GetCurrentProcess` is a pseudo-handle. Do not close it.
        let current = open_token(unsafe { GetCurrentProcess() })?;
        let client_user = token_user_bytes(client.0)?;
        let current_user = token_user_bytes(current.0)?;
        let equal = unsafe {
            let client_sid = (*client_user.as_ptr().cast::<TOKEN_USER>()).User.Sid;
            let current_sid = (*current_user.as_ptr().cast::<TOKEN_USER>()).User.Sid;
            EqualSid(client_sid, current_sid)
        };
        Ok(equal != 0)
    }

    pub fn current_thread_id() -> u32 {
        unsafe { GetCurrentThreadId() }
    }

    /// Result of a single cooperative stdin poll (piped stdin uses `PeekNamedPipe`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StdinPoll {
        Read(usize),
        Eof,
        Idle,
        Cancelled,
    }

    /// Read available piped stdin bytes without blocking when the pipe is empty.
    ///
    /// Returns [`StdinPoll::Idle`] after a short sleep when no bytes are ready.
    pub fn poll_stdin_read(
        out: &mut [u8],
        cancel: &std::sync::atomic::AtomicBool,
    ) -> io::Result<StdinPoll> {
        use std::sync::atomic::Ordering;
        use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;

        if cancel.load(Ordering::Relaxed) {
            return Ok(StdinPoll::Cancelled);
        }
        if out.is_empty() {
            return Ok(StdinPoll::Idle);
        }
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut avail = 0u32;
        let mut bytes_left = 0u32;
        let peek_ok = unsafe {
            PeekNamedPipe(
                handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut avail,
                &mut bytes_left,
            )
        };
        if peek_ok == 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(109) => Ok(StdinPoll::Eof),
                // Console and unsupported handles must not fall through to a
                // blocking ReadFile. A deadline cannot be kept that way.
                _ => Err(err),
            };
        }
        if avail == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
            return Ok(StdinPoll::Idle);
        }
        let cap = usize::try_from(avail).unwrap_or(out.len()).min(out.len());
        read_stdin_handle(handle, &mut out[..cap], cancel)
    }

    fn read_stdin_handle(
        handle: HANDLE,
        out: &mut [u8],
        cancel: &std::sync::atomic::AtomicBool,
    ) -> io::Result<StdinPoll> {
        use std::sync::atomic::Ordering;
        if cancel.load(Ordering::Relaxed) {
            return Ok(StdinPoll::Cancelled);
        }
        let to_read = u32::try_from(out.len()).unwrap_or(u32::MAX);
        let mut read = 0u32;
        let ok = unsafe {
            ReadFile(
                handle,
                out.as_mut_ptr().cast(),
                to_read,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(109) => Ok(StdinPoll::Eof),
                Some(995) => Ok(StdinPoll::Cancelled),
                Some(233) if read == 0 => Ok(StdinPoll::Idle),
                _ => Err(err),
            };
        }
        if read == 0 {
            return Ok(StdinPoll::Eof);
        }
        Ok(StdinPoll::Read(usize::try_from(read).unwrap_or(0)))
    }

    /// Cancel a blocked stdin `ReadFile` on `thread_id` so that thread can wipe and exit.
    pub fn cancel_thread_id(thread_id: u32) -> io::Result<()> {
        const THREAD_TERMINATE: u32 = 0x0001;
        let handle = unsafe { OpenThread(THREAD_TERMINATE, 0, thread_id) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let handle = Owned(handle);
        cancel_thread_io(handle.0 as isize)
    }

    /// Cancel a blocked stdin `ReadFile` on `thread` so that thread can wipe and exit.
    ///
    /// `ERROR_NOT_FOUND` means the thread has no pending call. The handle is not closed.
    fn cancel_thread_io(thread: isize) -> io::Result<()> {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CancelSynchronousIo(thread: HANDLE) -> i32;
        }
        let ok = unsafe { CancelSynchronousIo(thread as HANDLE) };
        if ok == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(1168) {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }

    fn open_token(process: HANDLE) -> io::Result<Owned> {
        let mut token: HANDLE = std::ptr::null_mut();
        let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Owned(token))
    }

    fn token_user_bytes(token: HANDLE) -> io::Result<Vec<u64>> {
        token_info_bytes(token, TokenUser)
    }

    fn token_info_bytes(
        token: HANDLE,
        class: windows_sys::Win32::Security::TOKEN_INFORMATION_CLASS,
    ) -> io::Result<Vec<u64>> {
        let mut needed = 0u32;
        let _ = unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let words = (needed as usize).div_ceil(8);
        let mut buffer = vec![0u64; words];
        let cap =
            u32::try_from(words * 8).map_err(|_| io::Error::other("token buffer too large"))?;
        let ok = unsafe {
            GetTokenInformation(
                token,
                class,
                buffer.as_mut_ptr().cast::<c_void>(),
                cap,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }

    struct Owned(HANDLE);

    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    struct LocalAlloc(HLOCAL);

    impl Drop for LocalAlloc {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(self.0);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

        const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn InitializeSecurityDescriptor(
                p_security_descriptor: PSECURITY_DESCRIPTOR,
                revision: u32,
            ) -> i32;
            fn SetSecurityDescriptorOwner(
                p_security_descriptor: PSECURITY_DESCRIPTOR,
                owner: PSID,
                owner_defaulted: i32,
            ) -> i32;
            fn SetSecurityDescriptorGroup(
                p_security_descriptor: PSECURITY_DESCRIPTOR,
                group: PSID,
                group_defaulted: i32,
            ) -> i32;
            fn SetSecurityDescriptorDacl(
                p_security_descriptor: PSECURITY_DESCRIPTOR,
                dacl_present: i32,
                dacl: *mut ACL,
                dacl_defaulted: i32,
            ) -> i32;
        }

        fn apply_absolute_security_descriptor(
            descriptor: *mut c_void,
            sid: PSID,
            acl: *mut ACL,
        ) -> io::Result<()> {
            let init =
                unsafe { InitializeSecurityDescriptor(descriptor, SECURITY_DESCRIPTOR_REVISION) };
            if init == 0 {
                return Err(io::Error::last_os_error());
            }
            let owner = unsafe { SetSecurityDescriptorOwner(descriptor, sid, 0) };
            let group = unsafe { SetSecurityDescriptorGroup(descriptor, sid, 0) };
            let dacl = unsafe { SetSecurityDescriptorDacl(descriptor, 1, acl, 0) };
            if owner == 0 || group == 0 || dacl == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Absolute security descriptor for the first named-pipe instance.
        ///
        /// The token user buffer keeps the owner SID pointer valid for the life
        /// of this value.
        #[allow(dead_code)]
        pub struct PipeSecurityAttributes {
            pub security_descriptor: Vec<u8>,
            pub acl: Vec<u32>,
            _sacl: HeapAcl,
            pub attributes: SECURITY_ATTRIBUTES,
            _sid_storage: Vec<u64>,
            _token: Owned,
        }

        impl PipeSecurityAttributes {
            pub fn for_current_user() -> io::Result<Self> {
                let token = open_token(unsafe { GetCurrentProcess() })?;
                let sid_storage = token_user_bytes(token.0)?;
                let sid = unsafe { (*sid_storage.as_ptr().cast::<TOKEN_USER>()).User.Sid };
                if sid.is_null() {
                    return Err(io::Error::other("current user sid missing"));
                }
                let mut acl_heap = user_only_acl(sid)?;
                let mut security_descriptor = vec![0u8; 128];
                let descriptor = security_descriptor.as_mut_ptr().cast::<c_void>();
                apply_absolute_security_descriptor(descriptor, sid, acl_heap.as_mut_ptr())?;
                let acl = acl_heap.0;
                let mut sacl = process_integrity_sacl()?;
                if unsafe {
                    windows_sys::Win32::Security::SetSecurityDescriptorSacl(
                        descriptor,
                        1,
                        sacl.as_mut_ptr(),
                        0,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                let attributes = SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: descriptor,
                    bInheritHandle: 0,
                };
                Ok(Self {
                    security_descriptor,
                    acl,
                    _sacl: sacl,
                    attributes,
                    _sid_storage: sid_storage,
                    _token: token,
                })
            }

            pub fn as_security_attributes(&self) -> *const SECURITY_ATTRIBUTES {
                std::ptr::from_ref(&self.attributes)
            }
        }

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CreateNamedPipeW(
                name: *const u16,
                open_mode: u32,
                pipe_mode: u32,
                max_instances: u32,
                out_buffer: u32,
                in_buffer: u32,
                default_timeout: u32,
                security: *const std::ffi::c_void,
            ) -> HANDLE;
            fn CreateFileW(
                name: *const u16,
                access: u32,
                share: u32,
                security: *const std::ffi::c_void,
                disposition: u32,
                flags: u32,
                template: HANDLE,
            ) -> HANDLE;
        }

        #[test]
        fn default_pipe_connectivity_control() {
            let name = format!(r"\\.\pipe\nexus-default-{}", std::process::id());
            let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let handle = unsafe {
                CreateNamedPipeW(wide.as_ptr(), 3 | 0x40000000, 8, 2, 64, 64, 0, ptr::null())
            };
            assert_ne!(
                handle,
                INVALID_HANDLE_VALUE,
                "create: {}",
                io::Error::last_os_error()
            );
            let _server = Owned(handle);
            let client = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    0xC0000000,
                    0,
                    ptr::null(),
                    3,
                    0x80,
                    ptr::null_mut(),
                )
            };
            assert_ne!(
                client,
                INVALID_HANDLE_VALUE,
                "default client: {}",
                io::Error::last_os_error()
            );
            drop(Owned(client));
        }

        #[test]
        fn unexpected_dacl_trustee_is_rejected() {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Security::{CreateWellKnownSid, WinWorldSid};
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let _entered = runtime.enter();
            let name = format!(r"\\.\pipe\nexus-reject-trustee-{}", std::process::id());
            let server = create_user_only_pipe(&name, true).expect("secure create");
            let mut world = [0u32; 17];
            let mut size = std::mem::size_of_val(&world) as u32;
            assert_ne!(
                unsafe {
                    CreateWellKnownSid(
                        WinWorldSid,
                        ptr::null_mut(),
                        world.as_mut_ptr().cast(),
                        &mut size,
                    )
                },
                0
            );
            // Fault injection on an empty, test-only pipe: an accidental broad
            // trustee must never satisfy the production descriptor validator.
            let mut bad_acl = user_only_acl(world.as_mut_ptr().cast()).expect("bad fixture ACL");
            let status = unsafe {
                SetSecurityInfo(
                    server.as_raw_handle() as HANDLE,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    bad_acl.as_mut_ptr(),
                    ptr::null_mut(),
                )
            };
            assert_eq!(status, ERROR_SUCCESS);
            assert!(
                assert_pipe_dacl_is_current_user_only(server.as_raw_handle() as isize).is_err()
            );
        }

        #[test]
        fn pipe_dacl_is_the_current_user_only() {
            let name = format!(r"\\.\pipe\nexus-ephemera-dacl-{}", std::process::id());
            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let mode = 3 | 0x4000_0000 | 0x0004_0000 | 0x0008_0000;
            let sec = PipeSecurityAttributes::for_current_user().expect("pipe security attrs");
            let handle = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    mode,
                    8,
                    2,
                    64,
                    64,
                    0,
                    sec.as_security_attributes().cast(),
                )
            };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                panic!("CreateNamedPipeW: {}", io::Error::last_os_error());
            }
            let handle = Owned(handle);
            // Apply on the live handle as well so the Tokio daemon path and this
            // unit test share the same owner, group, and DACL shape.
            lock_pipe_to_current_user(handle.0 as isize).expect("owner dacl");
            let _sec = sec;
            assert_pipe_integrity_matches_process(handle.0).expect("same integrity label");
            let client = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    0x8000_0000 | 0x4000_0000,
                    0,
                    ptr::null(),
                    3,
                    0x80,
                    std::ptr::null_mut(),
                )
            };
            if client.is_null() || client == INVALID_HANDLE_VALUE {
                panic!("client open: {}", io::Error::last_os_error());
            }
            drop(Owned(client));
            // The next instance asks only for duplex access. The ACE still
            // grants WRITE_DAC and WRITE_OWNER because the first instance's
            // open mode includes those bits.
            let second = unsafe {
                CreateNamedPipeW(wide.as_ptr(), 3 | 0x4000_0000, 8, 2, 64, 64, 0, ptr::null())
            };
            if second.is_null() || second == INVALID_HANDLE_VALUE {
                panic!("second instance: {}", io::Error::last_os_error());
            }
            let second = Owned(second);
            dacl_is_current_user_only(second.0, SE_KERNEL_OBJECT)
                .or_else(|_| dacl_is_current_user_only(second.0, SE_FILE_OBJECT))
                .expect("second instance keeps the owner dacl");
            let peer = pipe_server_peer(handle.0 as isize).expect("server pid");
            assert_eq!(peer.pid, std::process::id());
            assert!(peer.same_user);
        }
    }
}

#[cfg(windows)]
pub use windows::{
    PipePeer, StdinPoll, assert_pipe_dacl_is_current_user_only, cancel_thread_id,
    create_user_only_pipe, current_thread_id, lock_pipe_to_current_user, pipe_peer,
    pipe_server_peer, poll_stdin_read,
};
