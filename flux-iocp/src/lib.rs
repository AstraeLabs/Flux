//! Windows overlapped-I/O (IOCP) positional reads, behind a safe API.
//!
//! `flux` has `#![forbid(unsafe_code)]` crate-wide, so any raw Win32 FFI
//! (OVERLAPPED, I/O completion ports, ReadFile) has to live in a separate
//! crate. This is that crate: everything unsafe stays in here, `flux`
//! only ever calls [`OverlappedReader::open`] and [`OverlappedReader::read_all`].
//!
//! Why IOCP instead of a thread pool of blocking reads: a naive pool of
//! reader threads each calling a blocking positional read was tried first
//! and measured to be a net *regression* on real hardware (crypto and write
//! time on the main thread both roughly doubled) even after fixing an
//! initial bug (sharing one file handle across threads serializes on
//! Windows' per-handle cursor, even though `seek_read`'s offset argument is
//! independent of it) -- the remaining slowdown was genuine CPU/cache
//! contention between the extra OS threads and the main thread's AES-NI
//! decrypt loop. True overlapped I/O avoids spawning extra *busy* threads:
//! reads are issued asynchronously and this crate's single call to
//! `GetQueuedCompletionStatus` blocks efficiently (no spinning, no
//! concurrent CPU work) until the OS/driver has data ready.

#[cfg(windows)]
mod imp {
    use std::io;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_IO_PENDING, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    use windows_sys::Win32::System::IO::{
        CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
    };

    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
    const INFINITE: u32 = u32::MAX;

    #[repr(C)]
    struct IoRequest {
        overlapped: OVERLAPPED,
        job_id: usize,
        expected_len: usize,
        offset: u64,
        buf: Vec<u8>,
        partial_buf: Vec<u8>,
    }

    pub struct OverlappedReader {
        _file: std::fs::File,
        raw: HANDLE,
        iocp: HANDLE,
    }

    impl Drop for OverlappedReader {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.iocp);
            }
        }
    }

    impl OverlappedReader {
        pub fn open(path: &Path) -> io::Result<Self> {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_OVERLAPPED | FILE_FLAG_SEQUENTIAL_SCAN)
                .open(path)?;
            let raw = file.as_raw_handle() as HANDLE;
            let iocp = unsafe { CreateIoCompletionPort(raw, std::ptr::null_mut(), 0, 0) };
            if iocp.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                _file: file,
                raw,
                iocp,
            })
        }

        fn submit(&self, job_id: usize, offset: u64, len: usize) -> io::Result<()> {
            let mut req = Box::new(IoRequest {
                overlapped: unsafe { std::mem::zeroed() },
                job_id,
                expected_len: len,
                offset,
                buf: vec![0u8; len],
                partial_buf: Vec::new(),
            });
            req.overlapped.Anonymous.Anonymous.Offset = (offset & 0xFFFF_FFFF) as u32;
            req.overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
            let buf_ptr = req.buf.as_mut_ptr();
            let buf_len = req.buf.len() as u32;
            let raw_req = Box::into_raw(req);

            let ok = unsafe {
                ReadFile(
                    self.raw,
                    buf_ptr,
                    buf_len,
                    std::ptr::null_mut(),
                    raw_req as *mut OVERLAPPED,
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                    drop(unsafe { Box::from_raw(raw_req) });
                    return Err(err);
                }
            }
            Ok(())
        }

        pub fn read_all(
            &self,
            jobs: &[(u64, usize)],
            queue_depth: usize,
            mut on_complete: impl FnMut(usize, io::Result<Vec<u8>>) -> bool,
        ) -> io::Result<()> {
            let queue_depth = queue_depth.max(1);
            let mut next_submit = 0usize;
            let mut outstanding = 0usize;
            let mut keep_going = true;

            let fill = |next_submit: &mut usize,
                             outstanding: &mut usize,
                             on_complete: &mut dyn FnMut(usize, io::Result<Vec<u8>>) -> bool,
                             keep_going: &mut bool| {
                while *keep_going && *next_submit < jobs.len() && *outstanding < queue_depth {
                    let job_id = *next_submit;
                    let (offset, len) = jobs[job_id];
                    *next_submit += 1;
                    match self.submit(job_id, offset, len) {
                        Ok(()) => *outstanding += 1,
                        Err(e) => {
                            if !on_complete(job_id, Err(e)) {
                                *keep_going = false;
                            }
                        }
                    }
                }
            };

            fill(&mut next_submit, &mut outstanding, &mut on_complete, &mut keep_going);

            while outstanding > 0 {
                let mut bytes_transferred: u32 = 0;
                let mut completion_key: usize = 0;
                let mut lp_overlapped: *mut OVERLAPPED = std::ptr::null_mut();
                let ok = unsafe {
                    GetQueuedCompletionStatus(
                        self.iocp,
                        &mut bytes_transferred,
                        &mut completion_key,
                        &mut lp_overlapped,
                        INFINITE,
                    )
                };
                outstanding -= 1;

                if lp_overlapped.is_null() {
                    return Err(io::Error::last_os_error());
                }
                let req = unsafe { Box::from_raw(lp_overlapped as *mut IoRequest) };
                let IoRequest {
                    job_id,
                    expected_len,
                    offset,
                    mut buf,
                    partial_buf,
                    ..
                } = *req;

                let result = if ok == 0 {
                    Err(io::Error::last_os_error())
                } else if bytes_transferred as usize > expected_len {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "short read: more bytes transferred than requested",
                    ))
                } else if bytes_transferred as usize != expected_len {
                    if bytes_transferred == 0 {
                        buf.truncate(0);
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "short read: reached end of file before reading requested bytes",
                        ));
                    }
                    let remaining = expected_len - bytes_transferred as usize;
                    outstanding += 1;
                    let remaining_offset = offset + bytes_transferred as u64;
                    let partial = buf[..bytes_transferred as usize].to_vec();
                    let mut req = Box::new(IoRequest {
                        overlapped: unsafe { std::mem::zeroed() },
                        job_id,
                        expected_len: remaining,
                        offset: remaining_offset,
                        buf: vec![0u8; remaining],
                        partial_buf: partial,
                    });
                    req.overlapped.Anonymous.Anonymous.Offset =
                        (remaining_offset & 0xFFFF_FFFF) as u32;
                    req.overlapped.Anonymous.Anonymous.OffsetHigh =
                        (remaining_offset >> 32) as u32;
                    let buf_ptr = req.buf.as_mut_ptr();
                    let buf_len = req.buf.len() as u32;
                    let raw_req = Box::into_raw(req);
                    let ok = unsafe {
                        ReadFile(
                            self.raw,
                            buf_ptr,
                            buf_len,
                            std::ptr::null_mut(),
                            raw_req as *mut OVERLAPPED,
                        )
                    };
                    if ok == 0 {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                            drop(unsafe { Box::from_raw(raw_req) });
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "short read: fewer bytes transferred than requested",
                            ));
                        }
                    }
                    continue;
                } else {
                    let mut buf = buf;
                    if !partial_buf.is_empty() {
                        let mut full_buf = partial_buf;
                        full_buf.extend_from_slice(&buf);
                        buf = full_buf;
                    }
                    buf.truncate(expected_len);
                    Ok(buf)
                };

                if !on_complete(job_id, result) {
                    keep_going = false;
                }
                fill(&mut next_submit, &mut outstanding, &mut on_complete, &mut keep_going);
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
pub use imp::OverlappedReader;
