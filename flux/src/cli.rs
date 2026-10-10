use std::fmt;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use bitforge::Package;

#[cfg(feature = "cenc")]
mod codec_string;
#[cfg(feature = "cenc")]
mod dump;
#[cfg(feature = "cenc")]
mod extract_text;
#[cfg(feature = "cenc")]
mod key_sanity;
#[cfg(all(feature = "cli", feature = "cenc"))]
mod scan;

use crate::media::Media;
use crate::progressive::ProgressiveMux;

const BOX_FOURCC_OFFSET: usize = 4;
const ISOBMFF_LEADING_FOURCCS: [[u8; 4]; 4] = [*b"ftyp", *b"styp", *b"moov", *b"moof"];

const EBML_HEADER_MAGIC: [u8; 4] = [0x1A, 0x45, 0xDF, 0xA3];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Container {
    Mp4,
    Webm,
    Raw,
}

impl Container {
    pub fn name(&self) -> &'static str {
        match self {
            Container::Mp4 => "mp4",
            Container::Webm => "webm",
            Container::Raw => "raw",
        }
    }
}

bitforge::impl_spec_display!(Container);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutputFormat {
    Progressive,
    WebmDecrypt,
    Aes128Raw,
    TsSampleAes,
}

impl OutputFormat {
    pub fn name(&self) -> &'static str {
        match self {
            OutputFormat::Progressive => "progressive",
            OutputFormat::WebmDecrypt => "webm (in-place decrypt)",
            OutputFormat::Aes128Raw => "raw (aes-128-cbc decrypt)",
            OutputFormat::TsSampleAes => "mpeg-ts (experimental in-place sample-aes decrypt)",
        }
    }

    fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_ascii_lowercase().as_str() {
            "mp4" | "m4v" => Some(OutputFormat::Progressive),
            _ => None,
        }
    }
}

bitforge::impl_spec_display!(OutputFormat);

#[derive(Debug, clap::Parser)]
#[command(
    name = "flux",
    version = env!("CARGO_PKG_VERSION"),
    about = "By Arrowar",
    long_about = None,
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct Args {

    #[arg(short = 'h', long = "help", action = clap::ArgAction::Help, hide = true)]
    pub help: Option<bool>,

    #[arg(
        short = 'V',
        short_aliases = ['v'],
        long = "version",
        action = clap::ArgAction::Version,
        hide = true
    )]
    pub version: Option<bool>,

    #[arg(value_name = "IN", required_unless_present = "input")]
    pub in_positional: Option<PathBuf>,

    #[arg(
        short = 'i',
        long = "input",
        value_name = "PATH",
        conflicts_with = "in_positional",
        help_heading = "Input/Output"
    )]
    pub input: Option<PathBuf>,

    #[arg(
        short = 'o',
        long = "output",
        value_name = "PATH",
        required_unless_present_any = ["dump", "extract_text"],
        help_heading = "Input/Output"
    )]
    pub output: Option<PathBuf>,

    /// Output container format
    #[arg(short = 'f', long = "format", value_enum, help_heading = "Input/Output")]
    pub format: Option<FormatArg>,

    /// Comma-separated track IDs to keep (default: all)
    #[arg(long = "tracks", value_name = "IDS", value_delimiter = ',', help_heading = "Input/Output")]
    pub tracks: Vec<u32>,

    /// Print per-track metadata and exit (-j for pretty JSON)
    #[cfg(feature = "cenc")]
    #[arg(short = 'd', long = "dump", help_heading = "Inspect")]
    pub dump: bool,

    /// With `-d`/`--dump`: emit the metadata as pretty-printed JSON
    #[cfg(feature = "cenc")]
    #[arg(short = 'j', long = "json", requires = "dump", hide = true, help_heading = "Inspect")]
    pub json: bool,

    /// Extract a WebVTT-in-fMP4 (wvtt) subtitle track to a plain .vtt text
    /// file (requires -o/--output). If the input has more than one WebVTT
    /// subtitle track, narrow to one first with --tracks <ID>
    #[cfg(feature = "cenc")]
    #[arg(long = "extract-text", help_heading = "Inspect")]
    pub extract_text: bool,

    /// Content key for a protected track (repeatable, one per track)
    #[cfg(feature = "cenc")]
    #[arg(long = "key", value_name = "KID:KEY", help_heading = "CENC decrypt")]
    pub keys: Vec<String>,

    /// Decrypt a bare fragment against this init segment's moov
    #[cfg(feature = "cenc")]
    #[arg(long = "fragments-info", value_name = "INIT_PATH", help_heading = "CENC decrypt")]
    pub fragments_info: Option<PathBuf>,

    /// ffmpeg binary for the post-decrypt key-sanity check
    #[cfg(feature = "cenc")]
    #[arg(long = "ffmpeg-path", value_name = "PATH", help_heading = "CENC decrypt")]
    pub ffmpeg_path: Option<PathBuf>,

    /// Run the key-sanity check on this --fragments-info job (off there by default)
    #[cfg(feature = "cenc")]
    #[arg(long = "key-sanity-check", help_heading = "CENC decrypt")]
    pub key_sanity_check: bool,

    /// Skip the post-decrypt wrong-key check (avoids an ffmpeg spawn per
    /// file). Doesn't affect --fragments-info (off there by default already)
    #[cfg(feature = "cenc")]
    #[arg(long = "skip-key-sanity-check", help_heading = "CENC decrypt")]
    pub skip_key_sanity_check: bool,

    /// Writer-thread output buffer size, in KB (default: 64)
    #[cfg(feature = "cenc")]
    #[arg(long = "writer-buf-kb", value_name = "KB", help_heading = "Tuning")]
    pub writer_buf_kb: Option<u32>,

    /// Byte threshold (in KB) above which a decrypt run is split across
    /// worker threads (default: 512)
    #[cfg(feature = "cenc")]
    #[arg(long = "parallel-decrypt-min-kb", value_name = "KB", help_heading = "Tuning")]
    pub parallel_decrypt_min_kb: Option<u32>,

    /// Overlapped-read queue depth for the Windows IOCP read path (default: 8)
    #[cfg(feature = "cenc")]
    #[arg(long = "io-depth", value_name = "N", help_heading = "Tuning")]
    pub io_depth: Option<u32>,

    /// Disable the [profile] timing/per-track diagnostics (on by default).
    #[cfg(feature = "cenc")]
    #[arg(long = "no-profile", help_heading = "Diagnostics")]
    pub no_profile: bool,

    /// Persistent daemon mode: one JSON job per line on stdin, one JSON
    /// result per line on stdout, until EOF or a line that is --quit
    #[cfg(feature = "cenc")]
    #[arg(long = "daemon", help_heading = "Daemon mode")]
    pub daemon: bool,

    /// Whole-file HLS AES-128-CBC decrypt (bypasses CENC/MP4)
    #[cfg(feature = "sample-aes")]
    #[arg(long = "aes128", requires = "keys", help_heading = "Raw HLS decrypt (bypasses CENC)")]
    pub aes128: bool,

    /// EXPERIMENTAL: in-place decrypt for a protected MPEG-TS (auto-detects
    /// between HLS SAMPLE-AES [H.264/AAC only] and a second unrelated raw-.ts
    /// scheme with its own in-stream IV). Pair with --key <IV_or_KID>:<KEY>
    #[cfg(feature = "sample-aes")]
    #[arg(long = "sample-aes-ts", requires = "keys", help_heading = "Raw HLS decrypt (bypasses CENC)")]
    pub sample_aes_ts: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[non_exhaustive]
pub enum FormatArg {
    Progressive,
}

impl From<FormatArg> for OutputFormat {
    fn from(a: FormatArg) -> Self {
        match a {
            FormatArg::Progressive => OutputFormat::Progressive,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum CliError {
    Io(std::io::Error),
    Flux(crate::Error),
    UnknownContainer,
    UndeterminedFormat,
    NoTracksSelected,
    BadKey,
    UnsupportedSampleAes,
    KeySanityCheckFailed {
        track_id: u32,
        detail: String,
    },
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Io(e) => write!(f, "i/o error: {e}"),
            CliError::Flux(e) => write!(f, "flux error: {e}"),
            CliError::UnknownContainer => write!(
                f,
                "unknown input container: leading bytes match no supported format (MP4/CMAF)"
            ),
            CliError::UndeterminedFormat => write!(
                f,
                "output format not given and not inferable from the output extension; \
                 pass -f/--format"
            ),
            CliError::NoTracksSelected => {
                write!(f, "the --tracks selection matched no tracks in the input")
            }
            CliError::BadKey => {
                write!(f, "invalid --key: expected <32-hex-KID>:<32-hex-key>")
            }
            CliError::UnsupportedSampleAes => write!(
                f,
                "input carries a non-standard '4snf' box (SAMPLE-AES/FairPlay marker, not real \
                 CENC) -- this build has no decryptor for that scheme; use Shaka Packager instead \
                 of silently passing the track through undecrypted"
            ),
            CliError::KeySanityCheckFailed { track_id, detail } => write!(
                f,
                "decrypt likely failed: key is wrong for track {track_id}'s KID -- decoding the \
                 first decrypted frame produced invalid video ({detail}). CENC/AES-CTR has no \
                 built-in integrity check, so a wrong key still produces a same-length output; \
                 this is caught by test-decoding the first frame instead"
            ),
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e)
    }
}

impl From<crate::Error> for CliError {
    fn from(e: crate::Error) -> Self {
        CliError::Flux(e)
    }
}

pub type CliResult<T> = Result<T, CliError>;

pub fn detect_container(data: &[u8]) -> CliResult<Container> {
    if data.len() >= EBML_HEADER_MAGIC.len() && data[..EBML_HEADER_MAGIC.len()] == EBML_HEADER_MAGIC {
        return Ok(Container::Webm);
    }
    if data.len() >= BOX_FOURCC_OFFSET + 4 {
        let fourcc = &data[BOX_FOURCC_OFFSET..BOX_FOURCC_OFFSET + 4];
        if ISOBMFF_LEADING_FOURCCS.iter().any(|f| f == fourcc) {
            return Ok(Container::Mp4);
        }
    }
    Err(CliError::UnknownContainer)
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Output {
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Opts {
    pub format: OutputFormat,
    pub tracks: Vec<u32>,
}

fn filter_for_bmff_mux(media: &Media) -> CliResult<Media> {
    let dropped: Vec<u32> = media
        .tracks
        .iter()
        .filter(|t| !t.spec.config.is_muxable_in_bmff())
        .map(|t| t.spec.track_id)
        .collect();
    if dropped.is_empty() {
        return Ok(media.clone());
    }
    eprintln!(
        "warning: dropping track(s) {dropped:?} from the progressive MP4 output \
         (no ISOBMFF carriage in this crate for their codec)"
    );
    let mut media = media.clone();
    media.tracks.retain(|t| t.spec.config.is_muxable_in_bmff());
    if media.tracks.is_empty() {
        return Err(CliError::Flux(crate::Error::InvalidInput(
            "no track is muxable in ISOBMFF",
        )));
    }
    Ok(media)
}

fn package(media: &Media, opts: &Opts) -> CliResult<Output> {
    match opts.format {
        OutputFormat::Progressive => {
            let media = filter_for_bmff_mux(media)?;
            Ok(Output::Bytes(ProgressiveMux::new(true).package(&media)?))
        }
        OutputFormat::WebmDecrypt => Err(CliError::Flux(crate::Error::InvalidInput(
            "webm decrypt never goes through the Media-IR package() path",
        ))),
        OutputFormat::Aes128Raw => Err(CliError::Flux(crate::Error::InvalidInput(
            "raw aes-128-cbc decrypt never goes through the Media-IR package() path",
        ))),
        OutputFormat::TsSampleAes => Err(CliError::Flux(crate::Error::InvalidInput(
            "ts sample-aes decrypt never goes through the Media-IR package() path",
        ))),
    }
}

#[cfg(feature = "cenc")]
#[derive(Default)]
struct RuntimeConfig {
    skip_key_sanity_check: bool,
    writer_buf_kb: Option<usize>,
    parallel_decrypt_min_kb: Option<usize>,
    #[cfg_attr(not(windows), allow(dead_code))]
    io_depth: Option<usize>,
    profile: Option<bool>,
}

#[cfg(feature = "cenc")]
static RUNTIME_CONFIG: std::sync::OnceLock<RuntimeConfig> = std::sync::OnceLock::new();

#[cfg(feature = "cenc")]
fn runtime_config() -> &'static RuntimeConfig {
    RUNTIME_CONFIG.get_or_init(RuntimeConfig::default)
}

#[cfg(feature = "cenc")]
fn init_runtime_config(args: &Args) {
    let _ = RUNTIME_CONFIG.set(RuntimeConfig {
        skip_key_sanity_check: args.skip_key_sanity_check,
        writer_buf_kb: args.writer_buf_kb.map(|v| v as usize),
        parallel_decrypt_min_kb: args.parallel_decrypt_min_kb.map(|v| v as usize),
        io_depth: args.io_depth.map(|v| v as usize),
        profile: if args.no_profile { Some(false) } else { None },
    });
}

#[cfg(feature = "cenc")]
fn profile_enabled() -> bool {
    runtime_config().profile.unwrap_or(true)
}

#[cfg(feature = "cenc")]
fn first_encrypted_sync_sample_range(
    entries: &[crate::cenc::SampleEncryptionEntry],
    layouts: &[crate::cenc_decrypt::FragmentSampleLayout],
    sizes: &[usize],
) -> Option<(usize, usize)> {
    let mut offset = 0usize;
    for ((entry, layout), &size) in entries.iter().zip(layouts).zip(sizes) {
        if entry.is_encrypted && layout.is_sync {
            return Some((offset, size));
        }
        offset += size;
    }
    None
}

#[cfg(feature = "cenc")]
fn key_sanity_check_enabled() -> bool {
    !runtime_config().skip_key_sanity_check
}

fn writer_buf_capacity() -> usize {
    #[cfg(feature = "cenc")]
    let cli_kb = runtime_config().writer_buf_kb;
    #[cfg(not(feature = "cenc"))]
    let cli_kb: Option<usize> = None;

    cli_kb
        .map(|kb| kb * 1024)
        .unwrap_or(64 * 1024)
}

#[cfg(feature = "cenc")]
fn parallel_decrypt_threshold() -> usize {
    runtime_config()
        .parallel_decrypt_min_kb
        .map(|kb| kb * 1024)
        .unwrap_or(512 * 1024)
}

#[cfg(feature = "cenc")]
fn decrypt_run_maybe_parallel(
    crypto_track: &crate::cenc_decrypt::TrackCrypto,
    entries: &[crate::cenc::SampleEncryptionEntry],
    key: &[u8; 16],
    buf: &mut [u8],
    sizes: &[usize],
    scratch: &mut crate::cenc_decrypt::DecryptScratch,
) -> CliResult<()> {
    let total: usize = sizes.iter().sum();
    let n_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    if n_threads <= 1 || total < parallel_decrypt_threshold() || sizes.len() < n_threads {
        let mut pos = 0usize;
        for (i, &size) in sizes.iter().enumerate() {
            let sample = &mut buf[pos..pos + size];
            pos += size;
            crate::cenc_decrypt::decrypt_sample_slice(
                crypto_track.scheme,
                &crypto_track.tenc,
                &entries[i],
                key,
                sample,
                scratch,
            )?;
        }
        return Ok(());
    }

    let mut samples: Vec<&mut [u8]> = Vec::with_capacity(sizes.len());
    let mut rest = buf;
    for &size in sizes {
        let (head, tail) = rest.split_at_mut(size);
        samples.push(head);
        rest = tail;
    }

    let chunk = sizes.len().div_ceil(n_threads);
    let entry_groups: Vec<&[crate::cenc::SampleEncryptionEntry]> = entries.chunks(chunk).collect();

    let error: std::sync::Mutex<Option<crate::Error>> = std::sync::Mutex::new(None);
    std::thread::scope(|s| {
        let mut sample_iter = samples.into_iter();
        for entry_group in &entry_groups {
            let group: Vec<&mut [u8]> = sample_iter.by_ref().take(chunk).collect();
            let crypto_track = &*crypto_track;
            let error = &error;
            s.spawn(move || {
                let mut scratch = crate::cenc_decrypt::DecryptScratch::default();
                for (sample, entry) in group.into_iter().zip(entry_group.iter()) {
                    if let Err(e) = crate::cenc_decrypt::decrypt_sample_slice(
                        crypto_track.scheme,
                        &crypto_track.tenc,
                        entry,
                        key,
                        sample,
                        &mut scratch,
                    ) {
                        *error.lock().unwrap() = Some(e);
                        return;
                    }
                }
            });
        }
    });
    if let Some(e) = error.into_inner().unwrap() {
        return Err(e.into());
    }
    Ok(())
}

fn input_path(args: &Args) -> &Path {
    args.in_positional
        .as_deref()
        .or(args.input.as_deref())
        .expect("clap requires one of <IN> or --input")
}

fn resolve_format(args: &Args) -> CliResult<OutputFormat> {
    if let Some(f) = args.format {
        return Ok(f.into());
    }
    args.output
        .as_deref()
        .and_then(|p| p.extension())
        .and_then(|e| e.to_str())
        .and_then(OutputFormat::from_extension)
        .ok_or(CliError::UndeterminedFormat)
}

#[cfg(all(feature = "cli", feature = "cenc"))]
#[derive(serde::Deserialize)]
struct DaemonJob {
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    keys: Vec<String>,
    #[serde(default)]
    fragments_info: Option<String>,
    #[serde(default)]
    scan: Option<String>,
    #[serde(default)]
    ffmpeg_path: Option<String>,
    #[serde(default)]
    key_sanity: bool,
    #[serde(default)]
    aes128: bool,
}

#[cfg(all(feature = "cli", feature = "cenc"))]
#[derive(serde::Serialize)]
struct DaemonResult {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tracks: Option<Vec<scan::ScanTrack>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_cut: Option<u64>,
}

#[cfg(all(feature = "cli", feature = "cenc"))]
pub fn run_daemon() -> std::process::ExitCode {
    use std::io::{BufRead, BufReader};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    eprintln!("flux: daemon mode ready");
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let reader = BufReader::new(stdin.lock());

    for line in reader.lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "--quit" {
            break;
        }

        let result = match serde_json::from_str::<DaemonJob>(line) {
            Ok(job) => {
                if let Some(scan_path) = job.scan {
                    let t0 = std::time::Instant::now();
                    match catch_unwind(AssertUnwindSafe(|| scan::scan_chunk(Path::new(&scan_path)))) {
                        Ok(Ok((tracks, scan_cut))) => DaemonResult {
                            ok: true,
                            error: None,
                            elapsed_ms: Some(t0.elapsed().as_millis() as u64),
                            tracks: Some(tracks),
                            scan_cut,
                        },
                        Ok(Err(e)) => DaemonResult {
                            ok: false,
                            error: Some(e.to_string()),
                            elapsed_ms: Some(t0.elapsed().as_millis() as u64),
                            tracks: None,
                            scan_cut: None,
                        },
                        Err(_) => DaemonResult {
                            ok: false,
                            error: Some("panic during scan (job skipped, daemon still alive)".to_string()),
                            elapsed_ms: None,
                            tracks: None,
                            scan_cut: None,
                        },
                    }
                } else {
                    let t0 = std::time::Instant::now();
                    match (job.input, job.output) {
                        (Some(input), Some(output)) => {
                            let args = Args {
                                help: None,
                                version: None,
                                in_positional: None,
                                input: Some(PathBuf::from(&input)),
                                output: Some(PathBuf::from(&output)),
                        dump: false,
                        json: false,
                        extract_text: false,
                        format: Some(FormatArg::Progressive),
                    tracks: Vec::new(),
                    keys: job.keys,
                    fragments_info: job.fragments_info.as_ref().map(PathBuf::from),
                    ffmpeg_path: job.ffmpeg_path.as_ref().map(PathBuf::from),
                    key_sanity_check: job.key_sanity,
                    skip_key_sanity_check: false,
                    writer_buf_kb: None,
                    parallel_decrypt_min_kb: None,
                    io_depth: None,
                    no_profile: false,
                    daemon: false,
                    #[cfg(feature = "sample-aes")]
                    aes128: job.aes128,
                    #[cfg(feature = "sample-aes")]
                    sample_aes_ts: false,
                };
                match catch_unwind(AssertUnwindSafe(|| run(args))) {
                    Ok(Ok(_)) => DaemonResult {
                        ok: true,
                        error: None,
                        elapsed_ms: Some(t0.elapsed().as_millis() as u64),
                        tracks: None,
                        scan_cut: None,
                    },
                    Ok(Err(e)) => DaemonResult {
                        ok: false,
                        error: Some(e.to_string()),
                        elapsed_ms: Some(t0.elapsed().as_millis() as u64),
                        tracks: None,
                        scan_cut: None,
                    },
                    Err(_) => DaemonResult {
                        ok: false,
                        error: Some("panic during decrypt (job skipped, daemon still alive)".to_string()),
                        elapsed_ms: None,
                        tracks: None,
                        scan_cut: None,
                    },
                }
                        }
                        _ => DaemonResult {
                            ok: false,
                            error: Some("decrypt job needs input and output".to_string()),
                            elapsed_ms: Some(t0.elapsed().as_millis() as u64),
                            tracks: None,
                            scan_cut: None,
                        },
                    }
                }
            }
            Err(e) => DaemonResult {
                ok: false,
                error: Some(format!("bad job line: {e}")),
                elapsed_ms: None,
                tracks: None,
                scan_cut: None,
            },
        };

        let resp = serde_json::to_string(&result)
            .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"response serialize failure\"}".to_string());
        if writeln!(stdout, "{resp}").is_err() || stdout.flush().is_err() {
            break;
        }
    }

    std::process::ExitCode::SUCCESS
}

pub fn run(args: Args) -> CliResult<(Container, OutputFormat)> {
    #[cfg(not(feature = "cenc"))]
    return Err(CliError::Flux(crate::Error::InvalidInput(
        "this build requires the `cenc` feature (decrypt-to-progressive-MP4 is the only \
         supported operation)",
    )));

    #[cfg(feature = "cenc")]
    {
        init_runtime_config(&args);
        let in_path = input_path(&args).to_path_buf();

        if args.dump {
            dump::dump_streams(&in_path, &args.tracks, args.json)?;
            return Ok((Container::Mp4, OutputFormat::Progressive));
        }

        let output = args
            .output
            .as_deref()
            .expect("clap requires -o/--output unless --dump");

        if args.extract_text {
            extract_text::extract_text(&in_path, &args.tracks, output)?;
            return Ok((Container::Mp4, OutputFormat::Progressive));
        }

        #[cfg(feature = "sample-aes")]
        if args.aes128 {
            let spec = args.keys.first().ok_or_else(|| {
                CliError::Flux(crate::Error::InvalidInput(
                    "--aes128 requires a --key <IV>:<KEY> value",
                ))
            })?;
            let (iv, key) = parse_key(spec)?;
            stream_decrypt_aes128_cbc(&in_path, output, &key, &iv)?;
            return Ok((Container::Raw, OutputFormat::Aes128Raw));
        }

        #[cfg(feature = "sample-aes")]
        if args.sample_aes_ts {
            let spec = args.keys.first().ok_or_else(|| {
                CliError::Flux(crate::Error::InvalidInput(
                    "--sample-aes-ts requires a --key <IV_or_KID>:<KEY> value",
                ))
            })?;
            let (iv_or_kid, key) = parse_key(spec)?;
            let input = fs::read(&in_path)?;

            if crate::ts_bbts_decrypt::looks_like_bbts(&input) {
                eprintln!(
                    "flux: warning: --sample-aes-ts auto-detected the BBTS variant on this \
                     input (in-band base-IV marker found) -- this path is EXPERIMENTAL and has \
                     never been verified against real BBTS-protected content, only against a \
                     synthetic, self-built test asset. Treat its output as unverified."
                );
                let decrypted = crate::ts_bbts_decrypt::decrypt_ts_bbts(&input, &key)?;
                fs::write(output, &decrypted)?;
                return Ok((Container::Raw, OutputFormat::TsSampleAes));
            }

            eprintln!(
                "flux: warning: --sample-aes-ts is EXPERIMENTAL and has never been verified \
                 against real SAMPLE-AES-protected content -- only against a synthetic, \
                 self-built test asset. Treat its output as unverified."
            );
            let decrypted = crate::ts_sample_aes::decrypt_ts_sample_aes(&input, &key, &iv_or_kid)?;
            fs::write(output, &decrypted)?;
            return Ok((Container::Raw, OutputFormat::TsSampleAes));
        }

        if let Some(init_path) = &args.fragments_info {
            decrypt_fragment(
                init_path,
                &in_path,
                output,
                &args.keys,
                &args.tracks,
                args.ffmpeg_path.as_deref(),
                args.key_sanity_check,
            )?;
            return Ok((Container::Mp4, OutputFormat::Progressive));
        }

        if let Some(result) = try_decrypt_webm(&in_path, output, &args.keys)? {
            return Ok(result);
        }

        if input_has_fps_marker(&in_path)? {
            return Err(CliError::UnsupportedSampleAes);
        }

        let format = resolve_format(&args)?;

        let __profile = profile_enabled();
        let __tf = std::time::Instant::now();

        if format == OutputFormat::Progressive
            && stream_decrypt_to_progressive_mp4(
                &in_path,
                output,
                &args.keys,
                &args.tracks,
                args.ffmpeg_path.as_deref(),
            )?
        {
            return Ok((Container::Mp4, format));
        }

        if format == OutputFormat::Progressive
            && stream_decrypt_progressive_to_progressive_mp4(
                &in_path,
                output,
                &args.keys,
                &args.tracks,
                args.ffmpeg_path.as_deref(),
            )?
        {
            return Ok((Container::Mp4, format));
        }

        if __profile {
            eprintln!(
                "[profile][fallback] streaming path declined (input is not a fragmented moov+moof \
                 MP4/CMAF) -- falling back to whole-file in-memory decrypt+mux: {:?}",
                __tf.elapsed()
            );
        }

        let input = fs::read(&in_path)?;
        if __profile {
            eprintln!(
                "[profile][fallback] fs::read whole input: {:?} ({} bytes resident)",
                __tf.elapsed(),
                input.len()
            );
        }
        let container = detect_container(&input)?;

        let opts = Opts {
            format,
            tracks: args.tracks.clone(),
        };

        let mut media = decrypt_input(&input, container, &args.keys)?;
        if __profile {
            eprintln!(
                "[profile][fallback] decrypt_input (raw input + decrypted Media both \
                 resident): {:?}",
                __tf.elapsed()
            );
        }
        drop(input);
        if __profile {
            eprintln!(
                "[profile][fallback] dropped raw input, only decrypted Media resident: {:?}",
                __tf.elapsed()
            );
        }
        for track in &mut media.tracks {
            let new_timescale = crate::progressive::rescale_track_samples_if_needed(
                track.spec.timescale,
                &mut track.samples,
            );
            if __profile && new_timescale != track.spec.timescale {
                eprintln!(
                    "[profile][fallback][track {}] timescale {} would overflow a 32-bit tick \
                     accumulator over this track's duration (known VLC classic-mp4-demuxer \
                     issue) -- rescaled to {}",
                    track.spec.track_id, track.spec.timescale, new_timescale
                );
            }
            track.spec.timescale = new_timescale;
        }
        if !opts.tracks.is_empty() {
            media
                .tracks
                .retain(|t| opts.tracks.contains(&t.spec.track_id));
            if media.tracks.is_empty() {
                return Err(CliError::NoTracksSelected);
            }
        }
        let packaged = package(&media, &opts)?;
        if __profile {
            let Output::Bytes(ref b) = packaged;
            eprintln!(
                "[profile][fallback] package (decrypted Media + packaged output both \
                 resident, {} bytes packaged): {:?}",
                b.len(),
                __tf.elapsed()
            );
        }
        drop(media);
        if __profile {
            eprintln!(
                "[profile][fallback] dropped decrypted Media, only packaged output \
                 resident: {:?}",
                __tf.elapsed()
            );
        }
        write_output(output, packaged)?;
        if __profile {
            eprintln!("[profile][fallback] grand total: {:?}", __tf.elapsed());
            eprintln!("[profile] path: whole-file in-memory fallback");
        }
        Ok((container, format))
    }
}

fn write_output(out_path: &Path, out: Output) -> CliResult<()> {
    let Output::Bytes(b) = out;
    fs::write(out_path, b)?;
    Ok(())
}

#[cfg(feature = "sample-aes")]
fn stream_decrypt_aes128_cbc(
    in_path: &Path,
    out_path: &Path,
    key: &[u8; 16],
    iv: &[u8; 16],
) -> CliResult<()> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit, generic_array::GenericArray};
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    let __profile = profile_enabled();
    let __t0 = std::time::Instant::now();

    const CHUNK_LEN: usize = 1 << 20;

    let mut reader = BufReader::with_capacity(CHUNK_LEN, fs::File::open(in_path)?);
    let mut writer = BufWriter::with_capacity(writer_buf_capacity(), fs::File::create(out_path)?);
    let mut dec = Aes128CbcDec::new(key.into(), iv.into());

    let mut buf = vec![0u8; CHUNK_LEN];
    let mut pending_block: Option<[u8; 16]> = None;
    let mut total_in: u64 = 0;
    let mut had_partial_tail = false;
    loop {
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = reader.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        total_in += filled as u64;

        let whole_len = (filled / 16) * 16;
        for block in buf[..whole_len].chunks_exact_mut(16) {
            dec.decrypt_block_mut(GenericArray::from_mut_slice(block));
        }

        let mut pos = 0usize;
        while pos < whole_len {
            if let Some(prev) = pending_block.take() {
                writer.write_all(&prev)?;
            }
            pending_block = Some(buf[pos..pos + 16].try_into().expect("chunks_exact(16)"));
            pos += 16;
        }

        if whole_len < filled {
            had_partial_tail = true;
            if let Some(prev) = pending_block.take() {
                writer.write_all(&prev)?;
            }
            writer.write_all(&buf[whole_len..filled])?;
        }

        if filled < buf.len() {
            break;
        }
    }

    let pad_note: &'static str;
    if had_partial_tail {
        pad_note = "input length not a multiple of 16 -- trailing bytes passed through raw, no PKCS#7 check possible";
    } else if let Some(last) = pending_block {
        let pad_len = last[15] as usize;
        let valid_pkcs7 = (1..=16).contains(&pad_len) && last[16 - pad_len..].iter().all(|&b| b as usize == pad_len);
        if valid_pkcs7 {
            writer.write_all(&last[..16 - pad_len])?;
            pad_note = "valid PKCS#7 padding on final block, stripped";
        } else {
            writer.write_all(&last)?;
            pad_note = "no valid PKCS#7 padding on final block -- kept raw instead of stripping";
        }
    } else {
        pad_note = "empty input, nothing to decrypt";
    }

    writer.flush()?;

    if __profile {
        eprintln!(
            "[profile] aes128 stream decrypt: {:?} ({total_in} bytes in) -- {pad_note}",
            __t0.elapsed()
        );
    }

    Ok(())
}

#[cfg(feature = "cenc")]
fn decrypt_input(input: &[u8], container: Container, keys: &[String]) -> CliResult<Media> {
    use bitforge::Decrypt;

    if container != Container::Mp4 {
        return Err(CliError::Flux(crate::Error::InvalidInput(
            "--decrypt only applies to CENC-protected MP4/CMAF input",
        )));
    }
    let mut key_map = crate::cenc_decrypt::KeyMap::new();
    for spec in keys {
        let (kid, key) = parse_key(spec)?;
        key_map.insert(kid, key);
    }
    let decryptor = crate::cenc_decrypt::CencDecryptor::from_fmp4(input)?;
    let mut media = decryptor.demux()?;
    decryptor.decrypt(&mut media, &key_map)?;
    Ok(media)
}

struct TopLevelBox {
    box_type: [u8; 4],
    offset: u64,
    size: u64,
}

#[cfg(feature = "cenc")]
fn scan_top_level_boxes(file: &mut fs::File) -> CliResult<Vec<TopLevelBox>> {
    use crate::box_types::{BOX_HEADER_MIN_SIZE, BoxHeader, LARGESIZE_SIZE, UUID_TYPE_SIZE};
    use bitforge::Parse;

    let file_len = file.metadata()?.len();
    let mut boxes = Vec::new();
    let mut offset = 0u64;
    let mut header_buf = [0u8; BOX_HEADER_MIN_SIZE + LARGESIZE_SIZE + UUID_TYPE_SIZE];
    while offset < file_len {
        file.seek(SeekFrom::Start(offset))?;
        let want = (file_len - offset).min(header_buf.len() as u64) as usize;
        file.read_exact(&mut header_buf[..want])?;
        let header = BoxHeader::parse(&header_buf[..want])?;
        if header.size == 0 {
            return Err(CliError::Flux(crate::Error::InvalidInput(
                "top-level box with size 0 (to-EOF) is not supported by the \
                 streaming --decrypt scan",
            )));
        }
        boxes.push(TopLevelBox {
            box_type: header.box_type.0,
            offset,
            size: header.size,
        });
        offset += header.size;
    }
    Ok(boxes)
}

#[cfg(feature = "cenc")]
fn input_has_fps_marker(in_path: &Path) -> CliResult<bool> {
    let Ok(mut file) = fs::File::open(in_path) else {
        return Ok(false);
    };
    let Ok(top_level) = scan_top_level_boxes(&mut file) else {
        return Ok(false);
    };
    for b in &top_level {
        if &b.box_type == b"4snf" {
            return Ok(true);
        }
        const CONTAINER_TYPES: [[u8; 4]; 9] = [
            *b"moov", *b"trak", *b"mdia", *b"minf", *b"stbl", *b"mvex", *b"edts", *b"udta",
            *b"moof",
        ];
        if !CONTAINER_TYPES.contains(&b.box_type) {
            continue;
        }
        let mut buf = vec![0u8; b.size as usize];
        file.seek(SeekFrom::Start(b.offset))?;
        if file.read_exact(&mut buf).is_err() {
            continue;
        }
        if box_tree_contains(&buf[BOX_FOURCC_OFFSET + 4..], b"4snf") {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(feature = "cenc")]
fn box_tree_contains(data: &[u8], target: &[u8; 4]) -> bool {
    fn scan(data: &[u8], target: &[u8; 4], depth: u32) -> bool {
        if depth > 16 {
            return false;
        }
        use crate::box_types::BoxHeader;
        use bitforge::Parse;

        let mut offset = 0usize;
        while offset + 8 <= data.len() {
            let Ok(header) = BoxHeader::parse(&data[offset..]) else {
                break;
            };
            let hdr_len = header.header_size();
            let box_size = if header.size == 0 {
                data.len() - offset
            } else {
                header.size as usize
            };
            if box_size < hdr_len || offset + box_size > data.len() {
                break;
            }
            if header.box_type.is(target) {
                return true;
            }
            const CONTAINER_TYPES: [[u8; 4]; 9] = [
                *b"moov", *b"trak", *b"mdia", *b"minf", *b"stbl", *b"mvex", *b"edts", *b"udta",
                *b"moof",
            ];
            if CONTAINER_TYPES.iter().any(|t| header.box_type.is(t))
                && scan(&data[offset + hdr_len..offset + box_size], target, depth + 1)
            {
                return true;
            }
            offset += box_size;
        }
        false
    }
    scan(data, target, 0)
}

#[cfg(all(feature = "cenc", not(windows)))]
fn read_contiguous_run(
    file: &mut fs::File,
    layouts: &[crate::cenc_decrypt::FragmentSampleLayout],
    scratch: &mut Vec<u8>,
) -> CliResult<(usize, usize)> {
    let first = &layouts[0];
    let mut run_len = 1;
    let mut end = first.file_offset + first.size as u64;
    for layout in &layouts[1..] {
        if layout.file_offset != end {
            break;
        }
        end += layout.size as u64;
        run_len += 1;
    }
    let needed = (end - first.file_offset) as usize;
    if scratch.len() < needed {
        scratch.resize(needed, 0);
    }
    file.seek(SeekFrom::Start(first.file_offset))?;
    file.read_exact(&mut scratch[..needed])?;
    Ok((run_len, needed))
}

#[cfg(all(feature = "cenc", windows))]
fn open_sequential(path: &Path) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
}

#[cfg(all(feature = "cenc", not(windows)))]
fn open_sequential(path: &Path) -> std::io::Result<fs::File> {
    fs::File::open(path)
}

#[cfg(feature = "cenc")]
fn split_into_contiguous_runs(
    layouts: &[crate::cenc_decrypt::FragmentSampleLayout],
) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut i = 0;
    while i < layouts.len() {
        let mut end = layouts[i].file_offset + layouts[i].size as u64;
        let mut count = 1;
        while i + count < layouts.len() && layouts[i + count].file_offset == end {
            end += layouts[i + count].size as u64;
            count += 1;
        }
        runs.push((i, count));
        i += count;
    }
    runs
}

#[cfg(all(feature = "cenc", windows))]
fn io_depth() -> usize {
    runtime_config()
        .io_depth
        .filter(|&n| n > 0)
        .unwrap_or(8)
}

#[cfg(all(feature = "cenc", windows))]
#[allow(clippy::too_many_arguments)]
fn run_pass2(
    in_path: &Path,
    chunk_plan: &[(usize, usize, usize)],
    track_layout: &[Vec<crate::cenc_decrypt::FragmentSampleLayout>],
    track_crypto: &[Vec<crate::cenc::SampleEncryptionEntry>],
    target_track_ids: &[u32],
    track_codecs: &[crate::CodecConfig],
    crypto_tracks: &[crate::cenc_decrypt::TrackCrypto],
    track_keys: &[Option<[u8; 16]>],
    ffmpeg_path: Option<&Path>,
    p2_read: &mut std::time::Duration,
    p2_crypto: &mut std::time::Duration,
    buf_tx: &std::sync::mpsc::SyncSender<Vec<u8>>,
) -> CliResult<()> {
    let mut job_plan: Vec<(usize, usize, usize)> = Vec::new();
    let mut jobs: Vec<(u64, usize)> = Vec::new();
    for &(track_idx, start, count) in chunk_plan {
        let layouts = &track_layout[track_idx][start..start + count];
        for (local_start, local_count) in split_into_contiguous_runs(layouts) {
            let abs_start = start + local_start;
            let file_offset = track_layout[track_idx][abs_start].file_offset;
            let byte_len: usize = track_layout[track_idx][abs_start..abs_start + local_count]
                .iter()
                .map(|l| l.size as usize)
                .sum();
            job_plan.push((track_idx, abs_start, local_count));
            jobs.push((file_offset, byte_len));
        }
    }

    let queue_depth: usize = io_depth();

    let reader = flux_iocp::OverlappedReader::open(in_path)?;

    let mut pending: std::collections::HashMap<usize, std::io::Result<Vec<u8>>> =
        std::collections::HashMap::new();
    let mut next_expected = 0usize;
    let mut result: CliResult<()> = Ok(());
    let mut scratch = crate::cenc_decrypt::DecryptScratch::default();
    let key_sanity_on = key_sanity_check_enabled();
    let mut key_sanity_checked = vec![false; target_track_ids.len()];

    reader.read_all(&jobs, queue_depth, |job_id, r| {
        let __s = std::time::Instant::now();
        pending.insert(job_id, r);
        while let Some(r) = pending.remove(&next_expected) {
            let mut buf = match r {
                Ok(b) => b,
                Err(e) => {
                    result = Err(CliError::Io(e));
                    return false;
                }
            };
            *p2_read += __s.elapsed();

            let (track_idx, start, count) = job_plan[next_expected];
            let track_id = target_track_ids[track_idx];
            let crypto_track = crypto_tracks
                .iter()
                .find(|t| t.track_id == track_id)
                .expect("target_track_ids is drawn from crypto_tracks' own track_ids");
            let key = track_keys[track_idx];
            let entries = &track_crypto[track_idx][start..start + count];
            let layouts = &track_layout[track_idx][start..start + count];

            if let Some(key) = &key {
                let sizes: Vec<usize> = layouts.iter().map(|l| l.size as usize).collect();
                let __s = std::time::Instant::now();
                if let Err(e) =
                    decrypt_run_maybe_parallel(crypto_track, entries, key, &mut buf, &sizes, &mut scratch)
                {
                    result = Err(e);
                    return false;
                }
                *p2_crypto += __s.elapsed();
                if key_sanity_on && !key_sanity_checked[track_idx] {
                    if let Some((off, len)) = first_encrypted_sync_sample_range(entries, layouts, &sizes) {
                        key_sanity_checked[track_idx] = true;
                        if let Err(detail) =
                            key_sanity::check_first_sample(&track_codecs[track_idx], &buf[off..off + len], ffmpeg_path)
                        {
                            result = Err(CliError::KeySanityCheckFailed { track_id, detail });
                            return false;
                        }
                    }
                }
            }
            if buf_tx.send(buf).is_err() {
                result = Err(CliError::Flux(crate::Error::InvalidInput(
                    "writer thread died",
                )));
                return false;
            }
            next_expected += 1;
        }
        true
    })?;
    result
}

#[cfg(all(feature = "cenc", not(windows)))]
#[allow(clippy::too_many_arguments)]
fn run_pass2(
    file: &mut fs::File,
    chunk_plan: &[(usize, usize, usize)],
    track_layout: &[Vec<crate::cenc_decrypt::FragmentSampleLayout>],
    track_crypto: &[Vec<crate::cenc::SampleEncryptionEntry>],
    target_track_ids: &[u32],
    track_codecs: &[crate::CodecConfig],
    crypto_tracks: &[crate::cenc_decrypt::TrackCrypto],
    track_keys: &[Option<[u8; 16]>],
    ffmpeg_path: Option<&Path>,
    p2_read: &mut std::time::Duration,
    p2_crypto: &mut std::time::Duration,
    buf_tx: &std::sync::mpsc::SyncSender<Vec<u8>>,
) -> CliResult<()> {
    let mut scratch: Vec<u8> = Vec::with_capacity(4 << 20);
    let mut cbc_scratch = crate::cenc_decrypt::DecryptScratch::default();
    let key_sanity_on = key_sanity_check_enabled();
    let mut key_sanity_checked = vec![false; target_track_ids.len()];
    for &(track_idx, start, count) in chunk_plan {
        let track_id = target_track_ids[track_idx];
        let crypto_track = crypto_tracks
            .iter()
            .find(|t| t.track_id == track_id)
            .expect("target_track_ids is drawn from crypto_tracks' own track_ids");
        let key = track_keys[track_idx];
        let layouts = &track_layout[track_idx][start..start + count];
        let entries = &track_crypto[track_idx][start..start + count];

        let mut idx = 0;
        while idx < layouts.len() {
            let __s = std::time::Instant::now();
            let (run_len, run_bytes) = read_contiguous_run(file, &layouts[idx..], &mut scratch)?;
            *p2_read += __s.elapsed();
            let mut buf = scratch[..run_bytes].to_vec();
            if let Some(key) = &key {
                let sizes: Vec<usize> = layouts[idx..idx + run_len]
                    .iter()
                    .map(|l| l.size as usize)
                    .collect();
                let run_entries = &entries[idx..idx + run_len];
                let run_layouts = &layouts[idx..idx + run_len];
                let __s = std::time::Instant::now();
                decrypt_run_maybe_parallel(
                    crypto_track,
                    run_entries,
                    key,
                    &mut buf,
                    &sizes,
                    &mut cbc_scratch,
                )?;
                *p2_crypto += __s.elapsed();
                if key_sanity_on && !key_sanity_checked[track_idx] {
                    if let Some((off, len)) =
                        first_encrypted_sync_sample_range(run_entries, run_layouts, &sizes)
                    {
                        key_sanity_checked[track_idx] = true;
                        if let Err(detail) =
                            key_sanity::check_first_sample(&track_codecs[track_idx], &buf[off..off + len], ffmpeg_path)
                        {
                            return Err(CliError::KeySanityCheckFailed { track_id, detail });
                        }
                    }
                }
            }
            if buf_tx.send(buf).is_err() {
                return Err(CliError::Flux(crate::Error::InvalidInput(
                    "writer thread died",
                )));
            }
            idx += run_len;
        }
    }
    Ok(())
}

#[cfg(feature = "cenc")]
fn stream_decrypt_to_progressive_mp4(
    in_path: &Path,
    out_path: &Path,
    keys: &[String],
    tracks_filter: &[u32],
    ffmpeg_path: Option<&Path>,
) -> CliResult<bool> {
    use crate::cenc_decrypt::{self, KeyMap};
    use crate::media::Track;
    use crate::pipeline::TrackSpec;
    use crate::progressive::{ProgressiveMux, SampleMeta};

    let __profile = profile_enabled();
    let __t0 = std::time::Instant::now();
    let mut file = open_sequential(in_path)?;

    let mut head = [0u8; BOX_FOURCC_OFFSET + 4];
    if file.read_exact(&mut head).is_err() {
        return Ok(false);
    }
    if !ISOBMFF_LEADING_FOURCCS
        .iter()
        .any(|f| f == &head[BOX_FOURCC_OFFSET..BOX_FOURCC_OFFSET + 4])
    {
        return Ok(false);
    }

    let top_level = scan_top_level_boxes(&mut file)?;
    if __profile {
        eprintln!("[profile] scan_top_level_boxes: {:?}", __t0.elapsed());
    }
    let __t1 = std::time::Instant::now();
    let Some(moov_box) = top_level.iter().find(|b| &b.box_type == b"moov") else {
        return Ok(false);
    };
    let moof_boxes: Vec<&TopLevelBox> = top_level
        .iter()
        .filter(|b| &b.box_type == b"moof")
        .collect();
    if moof_boxes.is_empty() {
        return Ok(false);
    }

    let mut moov_bytes = vec![0u8; moov_box.size as usize];
    file.seek(SeekFrom::Start(moov_box.offset))?;
    file.read_exact(&mut moov_bytes)?;
    let (movie_timescale, specs) = cenc_decrypt::harvest_moov_track_specs(&moov_bytes)?;
    let crypto_tracks = cenc_decrypt::harvest_moov_crypto(&moov_bytes)?;
    let trex_defaults = cenc_decrypt::harvest_trex_defaults(&moov_bytes);
    drop(moov_bytes);
    if __profile {
        eprintln!("[profile] moov read+harvest: {:?}", __t1.elapsed());
    }
    let __t2 = std::time::Instant::now();

    if specs.is_empty() {
        return Err(CliError::Flux(crate::Error::UnexpectedBox {
            expected: "a protected AVC, HEVC, AV1, VP9, AAC, or Opus track",
        }));
    }

    let mut key_map = KeyMap::new();
    for spec in keys {
        let (kid, key) = parse_key(spec)?;
        key_map.insert(kid, key);
    }

    let track_specs: Vec<_> = specs
        .into_iter()
        .filter(|s| tracks_filter.is_empty() || tracks_filter.contains(&s.track_id))
        .filter(|s| {
            let keep = s.codec_config.is_muxable_in_bmff();
            if !keep && __profile {
                eprintln!(
                    "[profile][track {}] codec={} recognized but not remuxable into the \
                     progressive output (subtitle/opaque-data track carriage) -- excluded from \
                     output, not an error",
                    s.track_id,
                    codec_label(&s.codec_config)
                );
            }
            keep
        })
        .collect();
    if track_specs.is_empty() {
        return Err(CliError::NoTracksSelected);
    }
    let target_track_ids: Vec<u32> = track_specs.iter().map(|s| s.track_id).collect();
    let track_codecs: Vec<crate::CodecConfig> =
        track_specs.iter().map(|s| s.codec_config.clone()).collect();
    let mut tracks: Vec<Track> = track_specs
        .iter()
        .map(|s| {
            let mut spec = TrackSpec::new(s.track_id, s.timescale, s.codec_config.clone());
            spec.edit_list = s.edit_list.clone();
            Track::new(spec, Vec::new())
        })
        .collect();

    if __profile {
        for spec in &track_specs {
            let codec = codec_label(&spec.codec_config);
            match crypto_tracks.iter().find(|t| t.track_id == spec.track_id) {
                Some(t) if t.tenc.default_is_protected != 0 => {
                    let has_key = key_map.get(&t.tenc.default_kid).is_some();
                    eprintln!(
                        "[profile][track {}] codec={} protected: scheme={:?} \
                         kid={} iv_size={} pattern={}:{} constant_iv={} key_supplied={}",
                        spec.track_id,
                        codec,
                        t.scheme,
                        hex_kid(&t.tenc.default_kid),
                        t.tenc.default_per_sample_iv_size,
                        t.tenc.default_crypt_byte_block,
                        t.tenc.default_skip_byte_block,
                        t.tenc.default_constant_iv.is_some(),
                        has_key,
                    );
                    if !has_key {
                        eprintln!(
                            "[profile][track {}] WARNING: no --key matches this track's KID -- \
                             decrypt will fail",
                            spec.track_id
                        );
                    }
                }
                Some(_) => {
                    eprintln!(
                        "[profile][track {}] codec={} not protected (no sinf/tenc, or \
                         default_isProtected=0) -- passed through undecrypted",
                        spec.track_id, codec
                    );
                }
                None => {
                    eprintln!(
                        "[profile][track {}] codec={} no crypto metadata found (harvest_tracks \
                         skipped this track)",
                        spec.track_id, codec
                    );
                }
            }
            if is_he_aac(&spec.codec_config) {
                eprintln!(
                    "[profile][track {}] HE-AAC (SBR/PS) signaling detected -- a \
                     byte-for-byte ffmpeg framemd5 diff against mp4decrypt's (non-remuxed) \
                     output may show one extra leading silent frame here; this is a known \
                     ffmpeg fragmented-vs-progressive demux quirk, not a decrypt bug -- the \
                     decrypted audio content itself is unaffected",
                    spec.track_id
                );
            }
        }
    }

    let mut track_layout: Vec<Vec<cenc_decrypt::FragmentSampleLayout>> =
        alloc_vec_of_empty(target_track_ids.len());
    let mut track_crypto: Vec<Vec<crate::cenc::SampleEncryptionEntry>> =
        alloc_vec_of_empty(target_track_ids.len());
    let mut chunk_plan: Vec<(usize, usize, usize)> = Vec::new();
    let mut next_dts: std::collections::BTreeMap<u32, i64> = std::collections::BTreeMap::new();
    let mut __pass1_io = std::time::Duration::ZERO;
    let mut __pass1_parse = std::time::Duration::ZERO;
    let aux_file: Option<Vec<u8>> = if let Some(first) = moof_boxes.first() {
        let mut first_moof = vec![0u8; first.size as usize];
        file.seek(SeekFrom::Start(first.offset))?;
        file.read_exact(&mut first_moof)?;
        if cenc_decrypt::fragment_aux_info_requires_mdat(&first_moof) {
            Some(fs::read(in_path)?)
        } else {
            None
        }
    } else {
        None
    };
    for moof_box in &moof_boxes {
        let __s = std::time::Instant::now();
        let mut moof_bytes = vec![0u8; moof_box.size as usize];
        file.seek(SeekFrom::Start(moof_box.offset))?;
        file.read_exact(&mut moof_bytes)?;
        __pass1_io += __s.elapsed();

        let __s = std::time::Instant::now();
        let fragment_tracks = cenc_decrypt::harvest_fragment(
            moof_box.offset,
            &moof_bytes,
            &crypto_tracks,
            &target_track_ids,
            &mut next_dts,
            &trex_defaults,
            aux_file.as_deref(),
        )?;
        for ft in fragment_tracks {
            let track_idx = target_track_ids
                .iter()
                .position(|&id| id == ft.track_id)
                .expect("harvest_fragment only returns tracks from target_track_ids");
            let start = track_layout[track_idx].len();
            let count = ft.layout.len();
            if count > 0 {
                chunk_plan.push((track_idx, start, count));
            }
            track_layout[track_idx].extend(ft.layout);
            track_crypto[track_idx].extend(ft.crypto);
        }
        __pass1_parse += __s.elapsed();
    }
    if __profile {
        eprintln!(
            "[profile] pass1 total: {:?} (io={:?}, parse={:?}, {} moof)",
            __t2.elapsed(),
            __pass1_io,
            __pass1_parse,
            moof_boxes.len()
        );
    }
    let __t3 = std::time::Instant::now();

    let mut track_samples_meta: Vec<Vec<SampleMeta>> = track_layout
        .iter()
        .map(|layouts| {
            layouts
                .iter()
                .map(|l| SampleMeta {
                    duration: Some(l.duration),
                    composition_offset: (l.pts - l.dts) as i32,
                    size: l.size,
                    is_sync: l.is_sync,
                })
                .collect()
        })
        .collect();
    for (track_idx, track) in tracks.iter_mut().enumerate() {
        let new_timescale = crate::progressive::rescale_track_timing_if_needed(
            track.spec.timescale,
            &mut track_samples_meta[track_idx],
        );
        if __profile && new_timescale != track.spec.timescale {
            eprintln!(
                "[profile][track {}] timescale {} would overflow a 32-bit tick accumulator \
                 over this track's duration (known VLC classic-mp4-demuxer issue) -- rescaled \
                 to {}",
                track.spec.track_id, track.spec.timescale, new_timescale
            );
        }
        track.spec.timescale = new_timescale;
    }

    let mut track_chunks: Vec<Vec<(u64, u32)>> = alloc_vec_of_empty(target_track_ids.len());
    let mut __running_offset: u64 = 0;
    for &(track_idx, start, count) in &chunk_plan {
        let chunk_size: u64 = track_layout[track_idx][start..start + count]
            .iter()
            .map(|l| l.size as u64)
            .sum();
        track_chunks[track_idx].push((__running_offset, count as u32));
        __running_offset += chunk_size;
    }

    let header = ProgressiveMux::new(true).open_streaming_interleaved(
        &tracks,
        movie_timescale,
        &track_samples_meta,
        &track_chunks,
    )?;
    if __profile {
        eprintln!("[profile] open_streaming (build moov): {:?}", __t3.elapsed());
    }

    let mut out_file = fs::File::create(out_path)?;
    out_file.write_all(&header)?;
    drop(header);
    let mut __p2_read = std::time::Duration::ZERO;
    let mut __p2_crypto = std::time::Duration::ZERO;
    let __t4 = std::time::Instant::now();

    let (buf_tx, buf_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(4);
    let writer_handle = std::thread::spawn(move || -> std::io::Result<std::time::Duration> {
        let mut bw = std::io::BufWriter::with_capacity(writer_buf_capacity(), out_file);
        let mut written = std::time::Duration::ZERO;
        while let Ok(buf) = buf_rx.recv() {
            let __s = std::time::Instant::now();
            bw.write_all(&buf)?;
            written += __s.elapsed();
        }
        bw.flush()?;
        Ok(written)
    });

    let mut result: CliResult<()> = Ok(());

    let mut track_keys: Vec<Option<[u8; 16]>> = Vec::with_capacity(target_track_ids.len());
    'setup: for (track_idx, &track_id) in target_track_ids.iter().enumerate() {
        let crypto_track = crypto_tracks
            .iter()
            .find(|t| t.track_id == track_id)
            .expect("target_track_ids is drawn from crypto_tracks' own track_ids");
        let key = if crypto_track.tenc.default_is_protected != 0 {
            match key_map.get(&crypto_track.tenc.default_kid) {
                Some(k) => Some(*k),
                None => {
                    result = Err(CliError::Flux(crate::Error::InvalidInput(
                        "no content key for the track's default_KID",
                    )));
                    break 'setup;
                }
            }
        } else {
            None
        };
        if key.is_some() && track_layout[track_idx].len() != track_crypto[track_idx].len() {
            result = Err(CliError::Flux(crate::Error::InvalidInput(
                "sample count mismatch between trun and senc",
            )));
            break 'setup;
        }
        track_keys.push(key);
    }

    if result.is_ok() {
        result = run_pass2(
            #[cfg(windows)]
            in_path,
            #[cfg(not(windows))]
            &mut file,
            &chunk_plan,
            &track_layout,
            &track_crypto,
            &target_track_ids,
            &track_codecs,
            &crypto_tracks,
            &track_keys,
            ffmpeg_path,
            &mut __p2_read,
            &mut __p2_crypto,
            &buf_tx,
        );
    }
    drop(buf_tx);
    let __p2_write = match writer_handle.join() {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            if result.is_ok() {
                result = Err(CliError::Io(e));
            }
            std::time::Duration::ZERO
        }
        Err(_) => {
            if result.is_ok() {
                result = Err(CliError::Flux(crate::Error::InvalidInput("writer thread panicked")));
            }
            std::time::Duration::ZERO
        }
    };
    result?;
    if __profile {
        eprintln!(
            "[profile] pass2 total: {:?} (read={:?}, crypto={:?}, write={:?})",
            __t4.elapsed(),
            __p2_read,
            __p2_crypto,
            __p2_write
        );
        eprintln!("[profile] grand total: {:?}", __t0.elapsed());
        eprintln!("[profile] path: fragmented streaming (moov+moof)");
    }
    Ok(true)
}

#[cfg(feature = "cenc")]
fn hex_kid(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(feature = "cenc")]
fn read_bits(data: &[u8], bit_off: usize, bit_count: u32) -> Option<u32> {
    if bit_off + bit_count as usize > data.len() * 8 {
        return None;
    }
    let mut value: u32 = 0;
    for i in 0..bit_count as usize {
        let bit_idx = bit_off + i;
        let byte = data[bit_idx / 8];
        let bit = (byte >> (7 - (bit_idx % 8))) & 1;
        value = (value << 1) | bit as u32;
    }
    Some(value)
}

fn is_he_aac(cfg: &crate::CodecConfig) -> bool {
    let crate::CodecConfig::Aac { esds, .. } = cfg else {
        return false;
    };
    let Some(dsi) = esds
        .es_descriptor
        .decoder_config
        .as_ref()
        .and_then(|dc| dc.decoder_specific_info.as_ref())
    else {
        return false;
    };
    let data = &dsi.data;
    let mut pos: usize = 0;
    let mut next = |bits: u32| {
        let v = read_bits(data, pos, bits);
        pos += bits as usize;
        v
    };

    let Some(mut aot) = next(5) else {
        return false;
    };
    if aot == 31 {
        let Some(extra) = next(6) else {
            return false;
        };
        aot = 32 + extra;
    }
    let Some(sf_index) = next(4) else {
        return false;
    };
    if sf_index == 0xf && next(24).is_none() {
        return false;
    }
    if next(4).is_none() {
        return false;
    }

    if aot == 5 || aot == 29 {
        return true;
    }

    const GA_OBJECT_TYPES: &[u32] = &[1, 2, 3, 4, 6, 7, 17, 19, 20, 21, 22, 23];
    if !GA_OBJECT_TYPES.contains(&aot) {
        return false;
    }
    let (Some(_frame_length_flag), Some(depends_on_core)) = (next(1), next(1)) else {
        return false;
    };
    if depends_on_core == 1 && next(14).is_none() {
        return false;
    }
    if next(1).is_none() {
        return false;
    }

    matches!(next(11), Some(0x2b7)) && matches!(next(5), Some(5)) && matches!(next(1), Some(1))
}

fn codec_label(cfg: &crate::CodecConfig) -> &'static str {
    use crate::CodecConfig;
    match cfg {
        CodecConfig::Avc { .. } => "avc1 (H.264)",
        CodecConfig::Hevc { .. } => "hvc1/hev1 (H.265)",
        CodecConfig::Vvc { .. } => "vvc1/vvi1 (H.266)",
        CodecConfig::Av1 { .. } => "av01 (AV1)",
        CodecConfig::Vp9 { .. } => "vp09 (VP9)",
        CodecConfig::Aac { .. } => "mp4a (AAC)",
        CodecConfig::Ac3 { .. } => "ac-3",
        CodecConfig::Eac3 { .. } => "ec-3 (E-AC-3)",
        CodecConfig::Ac4 { .. } => "ac-4",
        CodecConfig::Opus { .. } => "Opus",
        CodecConfig::Flac { .. } => "fLaC",
        CodecConfig::Dts { .. } => "DTS",
        CodecConfig::MpegH { .. } => "MPEG-H 3D Audio",
        CodecConfig::MpegAudio { .. } => "MPEG-1/2 Audio",
        CodecConfig::Vorbis { .. } => "Vorbis",
        CodecConfig::Subtitle { .. } => "subtitle",
        CodecConfig::Mpeg2Video { .. } => "MPEG-2 Video",
        CodecConfig::Vp8 { .. } => "vp08 (VP8)",
    }
}

#[cfg(feature = "cenc")]
fn read_contiguous_run_stbl(
    file: &mut fs::File,
    layouts: &[crate::container::progressive_demux::StblSampleLayout],
    scratch: &mut Vec<u8>,
) -> CliResult<(usize, usize)> {
    let first = &layouts[0];
    let mut run_len = 1;
    let mut end = first.file_offset + first.size as u64;
    for layout in &layouts[1..] {
        if layout.file_offset != end {
            break;
        }
        end += layout.size as u64;
        run_len += 1;
    }
    let needed = (end - first.file_offset) as usize;
    if scratch.len() < needed {
        scratch.resize(needed, 0);
    }
    file.seek(SeekFrom::Start(first.file_offset))?;
    file.read_exact(&mut scratch[..needed])?;
    Ok((run_len, needed))
}

#[cfg(feature = "cenc")]
fn stream_decrypt_progressive_to_progressive_mp4(
    in_path: &Path,
    out_path: &Path,
    keys: &[String],
    tracks_filter: &[u32],
    ffmpeg_path: Option<&Path>,
) -> CliResult<bool> {
    use crate::cenc_decrypt::{self, KeyMap};
    use crate::container::progressive_demux::stbl_sample_layout;
    use crate::init_segment::MovieBox;
    use crate::media::Track;
    use crate::pipeline::TrackSpec;
    use crate::progressive::{ProgressiveMux, SampleMeta};
    use bitforge::Parse;

    let __profile = profile_enabled();
    let __t0 = std::time::Instant::now();
    let mut file = open_sequential(in_path)?;

    let mut head = [0u8; BOX_FOURCC_OFFSET + 4];
    if file.read_exact(&mut head).is_err() {
        return Ok(false);
    }
    if !ISOBMFF_LEADING_FOURCCS
        .iter()
        .any(|f| f == &head[BOX_FOURCC_OFFSET..BOX_FOURCC_OFFSET + 4])
    {
        return Ok(false);
    }

    let top_level = scan_top_level_boxes(&mut file)?;
    let Some(moov_box) = top_level.iter().find(|b| &b.box_type == b"moov") else {
        return Ok(false);
    };
    if top_level.iter().any(|b| &b.box_type == b"moof") {
        return Ok(false);
    }
    if __profile {
        eprintln!(
            "[profile][progressive] scan_top_level_boxes: {:?}",
            __t0.elapsed()
        );
    }
    let __t1 = std::time::Instant::now();

    let mut moov_bytes = vec![0u8; moov_box.size as usize];
    file.seek(SeekFrom::Start(moov_box.offset))?;
    file.read_exact(&mut moov_bytes)?;
    let aux_file: Vec<u8> = if cenc_decrypt::progressive_aux_info_requires_mdat(&moov_bytes) {
        fs::read(in_path)?
    } else {
        Vec::new()
    };
    let (movie_timescale, specs) = cenc_decrypt::harvest_moov_track_specs(&moov_bytes)?;
    let mut crypto_tracks = Vec::new();
    cenc_decrypt::harvest_tracks(
        if aux_file.is_empty() { &moov_bytes } else { &aux_file },
        &mut crypto_tracks,
    )?;
    let moov = MovieBox::parse(&moov_bytes)?;
    drop(moov_bytes);
    if __profile {
        eprintln!(
            "[profile][progressive] moov read+harvest: {:?}",
            __t1.elapsed()
        );
    }
    let __t2 = std::time::Instant::now();

    if specs.is_empty() {
        return Err(CliError::Flux(crate::Error::UnexpectedBox {
            expected: "a protected AVC, HEVC, AV1, VP9, AAC, or Opus track",
        }));
    }

    let mut key_map = KeyMap::new();
    for spec in keys {
        let (kid, key) = parse_key(spec)?;
        key_map.insert(kid, key);
    }

    let track_specs: Vec<_> = specs
        .into_iter()
        .filter(|s| tracks_filter.is_empty() || tracks_filter.contains(&s.track_id))
        .filter(|s| {
            let keep = s.codec_config.is_muxable_in_bmff();
            if !keep && __profile {
                eprintln!(
                    "[profile][track {}] codec={} recognized but not remuxable into the \
                     progressive output (subtitle/opaque-data track carriage) -- excluded from \
                     output, not an error",
                    s.track_id,
                    codec_label(&s.codec_config)
                );
            }
            keep
        })
        .collect();
    if track_specs.is_empty() {
        return Err(CliError::NoTracksSelected);
    }
    let target_track_ids: Vec<u32> = track_specs.iter().map(|s| s.track_id).collect();
    let track_codecs: Vec<crate::CodecConfig> =
        track_specs.iter().map(|s| s.codec_config.clone()).collect();
    let mut tracks: Vec<Track> = track_specs
        .iter()
        .map(|s| {
            let mut spec = TrackSpec::new(s.track_id, s.timescale, s.codec_config.clone());
            spec.edit_list = s.edit_list.clone();
            Track::new(spec, Vec::new())
        })
        .collect();

    if __profile {
        for spec in &track_specs {
            let codec = codec_label(&spec.codec_config);
            match crypto_tracks.iter().find(|t| t.track_id == spec.track_id) {
                Some(t) if t.tenc.default_is_protected != 0 => {
                    let has_key = key_map.get(&t.tenc.default_kid).is_some();
                    eprintln!(
                        "[profile][progressive][track {}] codec={} protected: scheme={:?} \
                         kid={} iv_size={} pattern={}:{} constant_iv={} key_supplied={}",
                        spec.track_id,
                        codec,
                        t.scheme,
                        hex_kid(&t.tenc.default_kid),
                        t.tenc.default_per_sample_iv_size,
                        t.tenc.default_crypt_byte_block,
                        t.tenc.default_skip_byte_block,
                        t.tenc.default_constant_iv.is_some(),
                        has_key,
                    );
                    if !has_key {
                        eprintln!(
                            "[profile][progressive][track {}] WARNING: no --key matches this \
                             track's KID -- decrypt will fail",
                            spec.track_id
                        );
                    }
                }
                Some(_) => {
                    eprintln!(
                        "[profile][progressive][track {}] codec={} not protected (no sinf/tenc, \
                         or default_isProtected=0) -- passed through undecrypted",
                        spec.track_id, codec
                    );
                }
                None => {
                    eprintln!(
                        "[profile][progressive][track {}] codec={} no crypto metadata found \
                         (harvest_tracks skipped this track)",
                        spec.track_id, codec
                    );
                }
            }
            if is_he_aac(&spec.codec_config) {
                eprintln!(
                    "[profile][progressive][track {}] HE-AAC (SBR/PS) signaling \
                     detected -- a byte-for-byte ffmpeg framemd5 diff against mp4decrypt's \
                     (non-remuxed) output may show one extra leading silent frame here; this \
                     is a known ffmpeg fragmented-vs-progressive demux quirk, not a decrypt \
                     bug -- the decrypted audio content itself is unaffected",
                    spec.track_id
                );
            }
        }
    }

    let mut track_layout: Vec<Vec<crate::container::progressive_demux::StblSampleLayout>> =
        Vec::with_capacity(target_track_ids.len());
    for &track_id in &target_track_ids {
        let trak = moov
            .tracks
            .iter()
            .find(|t| t.tkhd.track_id == track_id)
            .expect("target_track_ids is drawn from harvest_moov_track_specs' own track_ids");
        track_layout.push(stbl_sample_layout(trak)?);
    }
    if __profile {
        eprintln!("[profile][progressive] stbl layout harvest: {:?}", __t2.elapsed());
    }
    let __t3 = std::time::Instant::now();

    let mut track_samples_meta: Vec<Vec<SampleMeta>> = track_layout
        .iter()
        .map(|layouts| {
            layouts
                .iter()
                .map(|l| SampleMeta {
                    duration: Some(l.duration),
                    composition_offset: (l.pts - l.dts) as i32,
                    size: l.size,
                    is_sync: l.is_sync,
                })
                .collect()
        })
        .collect();
    for (track_idx, track) in tracks.iter_mut().enumerate() {
        let new_timescale = crate::progressive::rescale_track_timing_if_needed(
            track.spec.timescale,
            &mut track_samples_meta[track_idx],
        );
        if __profile && new_timescale != track.spec.timescale {
            eprintln!(
                "[profile][progressive][track {}] timescale {} would overflow a 32-bit tick \
                 accumulator over this track's duration (known VLC classic-mp4-demuxer issue) \
                 -- rescaled to {}",
                track.spec.track_id, track.spec.timescale, new_timescale
            );
        }
        track.spec.timescale = new_timescale;
    }
    let header =
        ProgressiveMux::new(true).open_streaming(&tracks, movie_timescale, &track_samples_meta)?;
    if __profile {
        eprintln!(
            "[profile][progressive] open_streaming (build moov): {:?}",
            __t3.elapsed()
        );
    }

    let mut out_file = fs::File::create(out_path)?;
    out_file.write_all(&header)?;
    drop(header);
    let mut __p2_read = std::time::Duration::ZERO;
    let mut __p2_crypto = std::time::Duration::ZERO;
    let __t4 = std::time::Instant::now();

    let (buf_tx, buf_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(2);
    let (free_tx, free_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    for _ in 0..2 {
        let _ = free_tx.send(Vec::with_capacity(4 << 20));
    }
    let writer_handle = std::thread::spawn(move || -> std::io::Result<std::time::Duration> {
        let mut bw = std::io::BufWriter::with_capacity(writer_buf_capacity(), out_file);
        let mut written = std::time::Duration::ZERO;
        while let Ok(buf) = buf_rx.recv() {
            let __s = std::time::Instant::now();
            bw.write_all(&buf)?;
            written += __s.elapsed();
            let _ = free_tx.send(buf);
        }
        bw.flush()?;
        Ok(written)
    });

    let mut result: CliResult<()> = Ok(());
    let mut cbc_scratch = crate::cenc_decrypt::DecryptScratch::default();
    let key_sanity_on = key_sanity_check_enabled();
    let mut key_sanity_checked = vec![false; target_track_ids.len()];
    'outer: for (track_idx, &track_id) in target_track_ids.iter().enumerate() {
        let crypto_track = crypto_tracks
            .iter()
            .find(|t| t.track_id == track_id)
            .expect("target_track_ids is drawn from crypto_tracks' own track_ids");
        let key = if crypto_track.tenc.default_is_protected != 0 {
            match key_map.get(&crypto_track.tenc.default_kid) {
                Some(k) => Some(*k),
                None => {
                    result = Err(CliError::Flux(crate::Error::InvalidInput(
                        "no content key for the track's default_KID",
                    )));
                    break 'outer;
                }
            }
        } else {
            None
        };
        let layouts = &track_layout[track_idx];
        let entries = &crypto_track.samples;
        if key.is_some() && layouts.len() != entries.len() {
            result = Err(CliError::Flux(crate::Error::InvalidInput(
                "sample count mismatch between stbl and senc",
            )));
            break 'outer;
        }

        let mut idx = 0;
        while idx < layouts.len() {
            let mut buf = match free_rx.recv() {
                Ok(b) => b,
                Err(_) => break 'outer,
            };
            let __s = std::time::Instant::now();
            let (run_len, run_bytes) = match read_contiguous_run_stbl(&mut file, &layouts[idx..], &mut buf) {
                Ok(v) => v,
                Err(e) => {
                    result = Err(e);
                    break 'outer;
                }
            };
            __p2_read += __s.elapsed();
            buf.truncate(run_bytes);
            let mut run_pos = 0usize;
            for (offset_in_run, layout) in layouts[idx..idx + run_len].iter().enumerate() {
                let size = layout.size as usize;
                let sample = &mut buf[run_pos..run_pos + size];
                run_pos += size;
                if let Some(key) = &key {
                    let __s = std::time::Instant::now();
                    if let Err(e) = cenc_decrypt::decrypt_sample_slice(
                        crypto_track.scheme,
                        &crypto_track.tenc,
                        &entries[idx + offset_in_run],
                        key,
                        sample,
                        &mut cbc_scratch,
                    ) {
                        result = Err(e.into());
                        break 'outer;
                    }
                    __p2_crypto += __s.elapsed();
                    if key_sanity_on
                        && !key_sanity_checked[track_idx]
                        && entries[idx + offset_in_run].is_encrypted
                        && layout.is_sync
                    {
                        key_sanity_checked[track_idx] = true;
                        if let Err(detail) =
                            key_sanity::check_first_sample(&track_codecs[track_idx], sample, ffmpeg_path)
                        {
                            result = Err(CliError::KeySanityCheckFailed { track_id, detail });
                            break 'outer;
                        }
                    }
                }
            }
            if buf_tx.send(buf).is_err() {
                break 'outer;
            }
            idx += run_len;
        }
    }
    drop(buf_tx);
    let __p2_write = match writer_handle.join() {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            if result.is_ok() {
                result = Err(CliError::Io(e));
            }
            std::time::Duration::ZERO
        }
        Err(_) => {
            if result.is_ok() {
                result = Err(CliError::Flux(crate::Error::InvalidInput("writer thread panicked")));
            }
            std::time::Duration::ZERO
        }
    };
    result?;
    if __profile {
        eprintln!(
            "[profile][progressive] pass2 total: {:?} (read={:?}, crypto={:?}, write={:?})",
            __t4.elapsed(),
            __p2_read,
            __p2_crypto,
            __p2_write
        );
        eprintln!("[profile][progressive] grand total: {:?}", __t0.elapsed());
        eprintln!("[profile] path: progressive streaming (moov, no moof)");
    }

    Ok(true)
}

#[cfg(feature = "cenc")]
fn scan_top_level_boxes_in_memory(data: &[u8]) -> CliResult<Vec<TopLevelBox>> {
    use crate::box_types::BoxHeader;
    use bitforge::Parse;

    let mut boxes = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let header = BoxHeader::parse(&data[offset..])?;
        if header.size == 0 {
            return Err(CliError::Flux(crate::Error::InvalidInput(
                "top-level box with size 0 (to-EOF) is not supported by \
                 --fragments-info",
            )));
        }
        boxes.push(TopLevelBox {
            box_type: header.box_type.0,
            offset: offset as u64,
            size: header.size,
        });
        offset += header.size as usize;
    }
    Ok(boxes)
}

#[cfg(feature = "cenc")]
#[allow(clippy::too_many_arguments)]
fn decrypt_fragment(
    init_path: &Path,
    in_path: &Path,
    out_path: &Path,
    keys: &[String],
    tracks_filter: &[u32],
    ffmpeg_path: Option<&Path>,
    key_sanity_check: bool,
) -> CliResult<()> {
    use crate::cenc_decrypt::{self, KeyMap};

    let init_bytes = fs::read(init_path)?;
    let moov_bytes = crate::media::find_top_box(&init_bytes, b"moov").ok_or(
        CliError::Flux(crate::Error::UnexpectedBox {
            expected: "moov (--fragments-info's init segment)",
        }),
    )?;
    let crypto_tracks = cenc_decrypt::harvest_moov_crypto(moov_bytes)?;
    let trex_defaults = cenc_decrypt::harvest_trex_defaults(moov_bytes);
    if crypto_tracks.is_empty() {
        return Err(CliError::Flux(crate::Error::UnexpectedBox {
            expected: "a protected AVC, HEVC, AV1, VP9, AAC, or Opus track in \
                       --fragments-info's init segment",
        }));
    }
    let track_codecs: std::collections::BTreeMap<u32, crate::CodecConfig> = if key_sanity_check {
        cenc_decrypt::harvest_moov_track_specs(moov_bytes)?
            .1
            .into_iter()
            .map(|s| (s.track_id, s.codec_config))
            .collect()
    } else {
        std::collections::BTreeMap::new()
    };

    let mut key_map = KeyMap::new();
    for spec in keys {
        let (kid, key) = parse_key(spec)?;
        key_map.insert(kid, key);
    }

    let target_track_ids: Vec<u32> = crypto_tracks
        .iter()
        .map(|t| t.track_id)
        .filter(|id| tracks_filter.is_empty() || tracks_filter.contains(id))
        .collect();
    if target_track_ids.is_empty() {
        return Err(CliError::NoTracksSelected);
    }
    let mut key_sanity_checked: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();

    let mut data = fs::read(in_path)?;
    let moof_boxes: Vec<(u64, u64)> = scan_top_level_boxes_in_memory(&data)?
        .iter()
        .filter(|b| &b.box_type == b"moof")
        .map(|b| (b.offset, b.size))
        .collect();
    if moof_boxes.is_empty() {
        if crate::media::find_top_box(&data, b"moov").is_some() {
            return rewrite_init_segment_clear(&data, out_path);
        }
        return Err(CliError::Flux(crate::Error::UnexpectedBox {
            expected: "moof (--fragments-info decrypts a bare fragment segment) or moov \
                       (a bare init segment, to be rewritten with a clear stsd)",
        }));
    }

    let mut next_dts: std::collections::BTreeMap<u32, i64> = std::collections::BTreeMap::new();
    let mut cbc_scratch = crate::cenc_decrypt::DecryptScratch::default();
    for &(moof_off, moof_size) in &moof_boxes {
        let moof_bytes = data[moof_off as usize..(moof_off + moof_size) as usize].to_vec();
        let fragment_tracks = cenc_decrypt::harvest_fragment(
            moof_off,
            &moof_bytes,
            &crypto_tracks,
            &target_track_ids,
            &mut next_dts,
            &trex_defaults,
            Some(&data),
        )?;
        drop(moof_bytes);

        for ft in fragment_tracks {
            let crypto_track = crypto_tracks
                .iter()
                .find(|t| t.track_id == ft.track_id)
                .expect("target_track_ids is drawn from crypto_tracks' own track_ids");
            if crypto_track.tenc.default_is_protected == 0 {
                continue;
            }
            let key = key_map.get(&crypto_track.tenc.default_kid).ok_or(
                CliError::Flux(crate::Error::InvalidInput(
                    "no content key for the track's default_KID",
                )),
            )?;
            if ft.layout.len() != ft.crypto.len() {
                return Err(CliError::Flux(crate::Error::InvalidInput(
                    "sample count mismatch between trun and senc",
                )));
            }

            let sizes: Vec<usize> = ft.layout.iter().map(|l| l.size as usize).collect();
            for (run_start, run_len) in split_into_contiguous_runs(&ft.layout) {
                let buf_start = ft.layout[run_start].file_offset as usize;
                let buf_end = buf_start + sizes[run_start..run_start + run_len].iter().sum::<usize>();
                if buf_end > data.len() {
                    return Err(CliError::Flux(crate::Error::BufferTooShort {
                        need: buf_end,
                        have: data.len(),
                        what: "fragment sample data (trun declares more bytes than the file actually has -- likely a truncated/incomplete download)",
                    }));
                }
                decrypt_run_maybe_parallel(
                    crypto_track,
                    &ft.crypto[run_start..run_start + run_len],
                    key,
                    &mut data[buf_start..buf_end],
                    &sizes[run_start..run_start + run_len],
                    &mut cbc_scratch,
                )?;
            }

            if key_sanity_check
                && !key_sanity_checked.contains(&ft.track_id)
                && let Some(idx) = ft
                    .layout
                    .iter()
                    .zip(ft.crypto.iter())
                    .position(|(l, e)| e.is_encrypted && l.is_sync)
            {
                key_sanity_checked.insert(ft.track_id);
                if let Some(cfg) = track_codecs.get(&ft.track_id) {
                    let start = ft.layout[idx].file_offset as usize;
                    let end = start + sizes[idx];
                    if let Err(detail) = key_sanity::check_first_sample(cfg, &data[start..end], ffmpeg_path) {
                        return Err(CliError::KeySanityCheckFailed {
                            track_id: ft.track_id,
                            detail,
                        });
                    }
                }
            }
        }
    }

    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0usize;
    let mut bytes_removed_before = 0u64;
    for (moof_off, moof_size) in &moof_boxes {
        let moof_off = *moof_off as usize;
        let moof_end = moof_off + *moof_size as usize;
        out.extend_from_slice(&data[pos..moof_off]);
        let (stripped, total_removed) =
            cenc_decrypt::strip_sample_encryption_boxes(&data[moof_off..moof_end], bytes_removed_before);
        out.extend_from_slice(&stripped);
        bytes_removed_before = total_removed;
        pos = moof_end;
    }
    out.extend_from_slice(&data[pos..]);

    fs::write(out_path, &out)?;
    Ok(())
}

#[cfg(feature = "cenc")]
fn rewrite_init_segment_clear(data: &[u8], out_path: &Path) -> CliResult<()> {
    use crate::cenc_decrypt;
    use crate::pipeline::TrackSpec;

    let moov_bytes = crate::media::find_top_box(data, b"moov").ok_or(CliError::Flux(
        crate::Error::UnexpectedBox { expected: "moov (bare init segment)" },
    ))?;
    let (movie_timescale, specs) = cenc_decrypt::harvest_moov_track_specs(moov_bytes)?;
    if specs.is_empty() {
        return Err(CliError::Flux(crate::Error::UnexpectedBox {
            expected: "a protected or unprotected AVC, HEVC, AV1, VP9, AAC, or Opus track \
                       in the bare init segment",
        }));
    }
    let tracks: Vec<TrackSpec> = specs
        .into_iter()
        .filter(|s| s.codec_config.is_muxable_in_bmff())
        .map(|s| {
            let mut spec = TrackSpec::new(s.track_id, s.timescale, s.codec_config);
            spec.edit_list = s.edit_list;
            spec
        })
        .collect();
    if tracks.is_empty() {
        return Err(CliError::NoTracksSelected);
    }
    let out_bytes = crate::pipeline::build_init_segment(&tracks, movie_timescale)?;
    fs::write(out_path, &out_bytes)?;
    Ok(())
}

#[cfg(feature = "cenc")]
fn try_decrypt_webm(
    in_path: &Path,
    out_path: &Path,
    keys: &[String],
) -> CliResult<Option<(Container, OutputFormat)>> {
    let mut head = [0u8; EBML_HEADER_MAGIC.len()];
    {
        let mut file = fs::File::open(in_path)?;
        if file.read_exact(&mut head).is_err() {
            return Ok(None);
        }
    }
    if head != EBML_HEADER_MAGIC {
        return Ok(None);
    }

    let input = fs::read(in_path)?;
    let key_pairs = keys.iter().map(|s| parse_key(s)).collect::<CliResult<Vec<_>>>()?;
    let output = crate::webm_decrypt::decrypt_webm(&input, &key_pairs)?;
    fs::write(out_path, &output)?;
    Ok(Some((Container::Webm, OutputFormat::WebmDecrypt)))
}

#[cfg(feature = "cenc")]
fn alloc_vec_of_empty<T>(n: usize) -> Vec<Vec<T>> {
    (0..n).map(|_| Vec::new()).collect()
}

#[cfg(feature = "cenc")]
fn parse_key(spec: &str) -> CliResult<([u8; 16], [u8; 16])> {
    let (kid_hex, key_hex) = spec
        .split_once(':')
        .ok_or(CliError::BadKey)?;
    let kid = parse_hex16(kid_hex).ok_or(CliError::BadKey)?;
    let key = parse_hex16(key_hex).ok_or(CliError::BadKey)?;
    Ok((kid, key))
}

#[cfg(feature = "cenc")]
fn parse_hex16(s: &str) -> Option<[u8; 16]> {
    let s = s.trim();
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}


#[cfg(all(test, feature = "cenc"))]
mod invalid_key_redaction_tests {
    use super::parse_key;

    #[test]
    fn invalid_key_errors_never_disclose_input() {
        const EXPECTED: &str = "invalid --key: expected <32-hex-KID>:<32-hex-key>";
        let marker = "sensitive-content-key-marker";
        let invalid_specs = [
            format!("{}:{marker}", "00".repeat(16)),
            format!("bad-kid:{}", "11".repeat(16)),
            "malformed-key-specification".to_string(),
        ];

        for spec in invalid_specs {
            let message = parse_key(&spec)
                .expect_err("invalid key specification must be rejected")
                .to_string();
            assert_eq!(message, EXPECTED);
            assert!(!message.contains(&spec));
            assert!(!message.contains(marker));
        }
    }

    #[test]
    fn valid_key_specifications_still_parse() {
        let specification = format!("{}:{}", "ab".repeat(16), "cd".repeat(16));
        let (kid, key) = parse_key(&specification).expect("valid key should parse");
        assert_eq!(kid, [0xab; 16]);
        assert_eq!(key, [0xcd; 16]);
    }
}
