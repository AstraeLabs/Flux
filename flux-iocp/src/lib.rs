//! Windows overlapped-I/O (IOCP)
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
    const MAX_READ_CHUNK: usize = 1 << 30;

    /// `overlapped` must stay the first field: the pointer the kernel hands back from
    /// `GetQueuedCompletionStatus` is cast back to `*mut IoRequest`.
    #[repr(C)]
    struct IoRequest {
        overlapped: OVERLAPPED,
        job_id: usize,
        /// Absolute file offset of the start of the job.
        offset: u64,
        /// Always exactly the job length; reads fill it front to back.
        buf: Vec<u8>,
        /// Number of bytes of `buf` already filled.
        filled: usize,
    }

    pub struct OverlappedReader {
        _file: std::fs::File,
        raw: HANDLE,
        iocp: HANDLE,
    }

    impl Drop for OverlappedReader {
        fn drop(&mut self) {
            // SAFETY: `iocp` is a handle created in `open` and owned exclusively by this
            // struct; it is closed exactly once here.
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
            // SAFETY: `raw` is a valid, open file handle opened with FILE_FLAG_OVERLAPPED
            // that outlives the port (`_file` is stored alongside). A null existing port
            // asks the API to create a new one.
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

        fn issue(&self, mut req: Box<IoRequest>) -> io::Result<()> {
            let remaining = (req.buf.len() - req.filled).min(MAX_READ_CHUNK);
            let buf_len = u32::try_from(remaining).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "read length exceeds u32")
            })?;
            let file_offset = req.offset.checked_add(req.filled as u64).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "file offset overflow")
            })?;

            req.overlapped = unsafe { std::mem::zeroed() };
            req.overlapped.Anonymous.Anonymous.Offset = (file_offset & 0xFFFF_FFFF) as u32;
            req.overlapped.Anonymous.Anonymous.OffsetHigh = (file_offset >> 32) as u32;
            let buf_ptr = unsafe { req.buf.as_mut_ptr().add(req.filled) };
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

        fn submit(&self, job_id: usize, offset: u64, len: usize) -> io::Result<()> {
            let mut buf = Vec::new();
            buf.try_reserve_exact(len).map_err(|_| {
                io::Error::new(io::ErrorKind::OutOfMemory, "cannot allocate read buffer")
            })?;
            buf.resize(len, 0);
            let req = Box::new(IoRequest {
                overlapped: unsafe { std::mem::zeroed() },
                job_id,
                offset,
                buf,
                filled: 0,
            });
            self.issue(req)
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
            let mut fatal: Option<io::Error> = None;

            let fill = |next_submit: &mut usize,
                        outstanding: &mut usize,
                        on_complete: &mut dyn FnMut(usize, io::Result<Vec<u8>>) -> bool,
                        keep_going: &mut bool| {
                while *keep_going && *next_submit < jobs.len() && *outstanding < queue_depth {
                    let job_id = *next_submit;
                    let (offset, len) = jobs[job_id];
                    *next_submit += 1;
                    if len == 0 {
                        if !on_complete(job_id, Ok(Vec::new())) {
                            *keep_going = false;
                        }
                        continue;
                    }
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

                if lp_overlapped.is_null() {
                    return Err(io::Error::last_os_error());
                }
                outstanding -= 1;
                let mut req = unsafe { Box::from_raw(lp_overlapped as *mut IoRequest) };

                let failure: Option<io::Error> = if ok == 0 {
                    Some(io::Error::last_os_error())
                } else {
                    let n = bytes_transferred as usize;
                    if n > req.buf.len() - req.filled {
                        Some(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "short read: more bytes transferred than requested",
                        ))
                    } else if n == 0 {
                        Some(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "short read: reached end of file before reading requested bytes",
                        ))
                    } else {
                        req.filled += n;
                        None
                    }
                };

                if let Some(e) = failure {
                    if fatal.is_none() && keep_going {
                        fatal = Some(e);
                    }
                    keep_going = false;
                    continue;
                }

                if req.filled < req.buf.len() {
                    if !keep_going {
                        continue;
                    }
                    // Partial read: re-issue the tail into the same buffer.
                    match self.issue(req) {
                        Ok(()) => outstanding += 1,
                        Err(e) => {
                            if fatal.is_none() {
                                fatal = Some(e);
                            }
                            keep_going = false;
                        }
                    }
                    continue;
                }

                let IoRequest { job_id, buf, .. } = *req;
                if keep_going && !on_complete(job_id, Ok(buf)) {
                    keep_going = false;
                }
                fill(&mut next_submit, &mut outstanding, &mut on_complete, &mut keep_going);
            }
            match fatal {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }
}

#[cfg(windows)]
pub use imp::OverlappedReader;

#[cfg(all(test, windows))]
mod tests {
    use super::OverlappedReader;
    use std::io::Write;

    fn temp_file(len: usize) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("flux-iocp-test-{}-{}.bin", std::process::id(), len));
        let mut f = std::fs::File::create(&p).unwrap();
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        f.write_all(&data).unwrap();
        p
    }

    #[test]
    fn reads_exact_job_lengths() {
        let path = temp_file(100_000);
        let r = OverlappedReader::open(&path).unwrap();
        let jobs = [(0u64, 10usize), (10, 0), (50_000, 49_999), (99_999, 1)];
        let mut got: Vec<Option<Vec<u8>>> = vec![None; jobs.len()];
        r.read_all(&jobs, 3, |id, res| {
            got[id] = Some(res.unwrap());
            true
        })
        .unwrap();
        for (i, &(off, len)) in jobs.iter().enumerate() {
            let b = got[i].as_ref().unwrap();
            assert_eq!(b.len(), len);
            for (k, &v) in b.iter().enumerate() {
                assert_eq!(v, ((off as usize + k) % 251) as u8);
            }
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn eof_is_an_error_and_drains() {
        let path = temp_file(1000);
        let r = OverlappedReader::open(&path).unwrap();
        let jobs = [(0u64, 500usize), (900, 500), (0, 100)];
        let res = r.read_all(&jobs, 3, |_, _| true);
        assert!(res.is_err());
        // A second call on the same reader must not see stale packets.
        let mut ok = false;
        r.read_all(&[(0, 10)], 1, |_, b| {
            ok = b.unwrap().len() == 10;
            true
        })
        .unwrap();
        assert!(ok);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn impossible_job_length_is_an_error() {
        let path = temp_file(10);
        let r = OverlappedReader::open(&path).unwrap();
        let mut errs = 0;
        r.read_all(&[(0, usize::MAX)], 1, |_, res| {
            assert!(res.is_err());
            errs += 1;
            true
        })
        .unwrap();
        assert_eq!(errs, 1);
        std::fs::remove_file(path).ok();
    }
}
