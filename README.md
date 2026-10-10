# Flux

Flux is a command-line tool that decrypts CENC-protected MP4 / CMAF / fMP4 media (plus some WebM and MPEG-TS) when you give it the content keys, and writes a plain, playable progressive MP4.

Supported protection schemes: `cenc` (AES-CTR), `cbcs`, `cbc1`, `cens`.

## Quick start

```bash
# Decrypt an encrypted MP4 with one key (KID:KEY, 32 hex chars each)
flux input.mp4 -o output.mp4 --key 00112233445566778899aabbccddeeff:ffeeddccbbaa99887766554433221100

# Decrypt a bare fragment using its init segment
flux fragment.m4s -o output.mp4 --fragments-info init.mp4 --key <KID>:<KEY>

# Show track metadata (add -j for JSON)
flux input.mp4 --dump
flux input.mp4 --dump --json

# Extract a WebVTT-in-MP4 subtitle track
flux input.mp4 --extract-text -o subs.vtt
```

Only `--key` values matter for decryption: keys are never read from environment variables. Note that anything passed on the command line is visible to other local users in the process list, and Flux never prints a key value in error messages.

## Options

| Flag | Description |
|---|---|
| `<IN>` / `-i, --input <PATH>` | Input file (positional or `-i`, not both). |
| `-o, --output <PATH>` | Output file. Required unless `--dump`. Must differ from the input. |
| `-f, --format <FORMAT>` | Only `progressive`. Inferred from `.mp4` / `.m4v`. |
| `--tracks <IDS>` | Comma-separated track IDs to keep (default: all). |
| `-d, --dump` | Print track metadata and exit. |
| `-j, --json` | With `--dump`: pretty JSON output. |
| `--extract-text` | Extract a `wvtt` track to `.vtt` (needs `-o`; use `--tracks` if several). |
| `--key <KID:KEY>` | Content key, repeatable. |
| `--fragments-info <INIT>` | Decrypt a bare fragment using this init segment. |
| `--ffmpeg-path <PATH>` | `ffmpeg` binary used for the wrong-key check (default: `ffmpeg` on `PATH`). |
| `--key-sanity-check` | Run the wrong-key check on a `--fragments-info` job. |
| `--skip-key-sanity-check` | Skip the post-decrypt wrong-key check. |
| `--writer-buf-kb <KB>` | Output buffer size (default 64). |
| `--parallel-decrypt-min-kb <KB>` | Size above which decryption is split across threads (default 512). |
| `--io-depth <N>` | Windows overlapped-read queue depth (default 8, ignored elsewhere). |
| `--no-profile` | Disable the timing diagnostics printed to stderr. |
| `--daemon` | Persistent mode, see below. Must be the first argument. |
| `--aes128` | Raw HLS AES-128-CBC file decrypt, `--key <IV>:<KEY>` (needs `sample-aes` feature). |
| `--sample-aes-ts` | Experimental in-place MPEG-TS SAMPLE-AES decrypt (needs `sample-aes` feature). |

There are no environment variables. Exit code is `0` on success and `1` on any error.

The wrong-key check runs `ffmpeg` on the first decrypted frame, because CENC has no integrity check and a wrong key yields garbage of the same size. It needs `ffmpeg` on `PATH` (or `--ffmpeg-path`), and is on by default for normal decrypts.

Inputs carrying a `4snf` box (FairPlay-style SAMPLE-AES, not CENC) are refused.

## Daemon mode

`flux --daemon` reads one JSON job per line on stdin and writes one JSON result per line on stdout. It stops on EOF or a line that is exactly `--quit`.

```json
{"input":"in.mp4","output":"out.mp4","keys":["<KID>:<KEY>"]}
{"scan":"chunk.m4s"}
```

Results look like `{"ok":true,"elapsed_ms":12}` or `{"ok":false,"error":"..."}`. Job paths are used as given, so only feed the daemon from a trusted source.

## Workspace

| Crate | Purpose |
|---|---|
| `flux` | Library and CLI. |
| `bitforge` | Bit reader/writer, hex, CRC, CENC enums. |
| `eventframe` | `emsg` event box handling. |
| `flux-iocp` | Windows overlapped file reads (all the `unsafe` lives here). |

Cargo features of `flux`: `std`, `serde`, `cenc` (default), `sample-aes`, and `cli` (needed for the binary).

## Build and test

Requires the Rust toolchain pinned in `rust-toolchain.toml` (1.95.0). `ffmpeg` is optional at runtime.

```bash
cargo build --locked --release -p flux --all-features
cargo test --locked --workspace --all-features
```

The binary is `target/release/flux` (`flux.exe` on Windows).

## Releases

Every push to `main` rebuilds the binaries and uploads them, with a `SHA256SUMS` file, to the `Init` release: Windows (x64, arm64), macOS (x64, arm64), Linux (glibc x64 and arm64, musl x64) and Termux (arm64, arm). Verify downloads with `sha256sum -c SHA256SUMS`.

## License

AGPL-3.0, see `LICENSE`.
