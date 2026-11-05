# Benchmark: Flux vs Shaka Packager vs Bento4

Decryption speed, CPU use and memory of three CENC decryptors on real, encrypted 4K HEVC video, measured inside Docker
(`debian:bookworm-slim`, x86_64):

| Tool | Version | Command used (its own default) |
|---|---|---|
| Flux | built from this checkout (`cargo build --release -p flux --all-features`) | `flux IN -o OUT --key KID:KEY` |
| Shaka Packager | v3.9.3 (prebuilt, SHA256 pinned) | `packager in=IN,stream=video,output=OUT --enable_raw_key_decryption --keys label=..:key_id=..:key=..` |
| Bento4 `mp4decrypt` | 1.6.0-641 (prebuilt, SHA256 pinned) | `mp4decrypt --key KID:KEY IN OUT` |

The same Shaka and Bento4 versions are the independent oracles used by `flux/tests/fixtures/corpus`.

## What is measured

Each run is one `wait4()` on the tool, so only the tool is timed: **wall time**, **CPU time** (user + sys), **average cores
busy** (CPU time / wall time) and **peak RSS** (the largest resident set of the tool and anything it spawned, for example the
`ffmpeg` of Flux's wrong-key check). Output size is recorded too.

Scenarios (`bench.py` `SCENARIOS`):

| Mode | Scenario | What it stands for |
|---|---|---|
| whole file | Shaka, Bento4, Flux default | the plain "decrypt this file" comparison, each tool with its own output (Flux: progressive MP4; Bento4: fragmented MP4; Shaka: remuxed fragmented MP4) |
| whole file | `flux --skip-key-sanity-check` | the same without the `ffmpeg` wrong-key check (a fixed cost of a few hundred ms) |
| whole file | `flux --daemon`, one job for the whole file | daemon overhead vs the plain CLI |
| whole file | `flux --in-place` | size-preserving decrypt on a copy of the input (the copy is made before the timed run) |
| streaming | `flux --chunks DIR -o file`, `-o - --tfdt-rebase`, `--in-place` | decrypt the downloaded `seg_<n>.mp4` chunks directly, no merge step |
| live | `flux --fragments-info` (one process per fragment) | a downloader that spawns the decryptor for every segment |
| live | `flux --daemon` (one process, one JSON job per fragment) | the same through the persistent daemon |
| live | `mp4decrypt --fragments-info` (one process per fragment) | the Bento4 equivalent, the baseline for the two rows above |

Download time is recorded by `fetch.sh` (`download.json`: wall time of N_m3u8DL-RE for the same fragments, with 28
connections, including its own merge). The report turns it into two live numbers: **x real time** (seconds of video decrypted
per second of wall time) and **% of download time** (decrypt wall time / download time; under 100% a live pipeline is
download-bound, not decrypt-bound).

### Cold cache

The page cache is dropped (`echo 3 > /proc/sys/vm/drop_caches`, which is why the container runs `--privileged`) before **every**
run, warm-up included, so each run reads its input from the disk and a faster second run cannot come from the cache. Anything
prepared for a run (the copy for `--in-place`) is written, `sync`ed and then the cache is dropped, before the clock starts. The
report header says which method was used. The Docker Desktop disk is a virtual disk (VHDX); the Windows host may cache that
file, which a container cannot control. Without `--privileged` the script falls back to `posix_fadvise(DONTNEED)` on the input
only, and says so; `--warm` turns the dropping off.

### Correctness

A speed number is worthless if the output is wrong, so every output is checked: the md5 of the clear video packets
(`ffmpeg -c copy -f md5`, the method of `corpus/manifest.json`) must be the same for all tools of the same mode (for fragment
jobs: every 10th fragment), and `ffmpeg` must decode the last seconds of the raw output (**Plays as-is**). Some decryptors leave
`senc`/`saiz`/`saio` boxes behind and ffmpeg then refuses the file; for the comparison those boxes are renamed `free` on the
output (what Flux does itself), and the report says so.

## Reproduce

```bash
cp bench/titles.example.json .test-streams/bench/titles.local.json   # fill in manifests, keys, range
bench/fetch.sh --bin /path/to/N_m3u8DL-RE      # downloads the ENCRYPTED video track, no --key
bench/docker-bench.sh                          # build the image, run "all cores" and "1 core"
CPUSETS="all 0 0-3" bench/docker-bench.sh --runs 3 --ids my-title
```

`titles.local.json` holds manifest URLs with tokens and content keys: it lives in the git-ignored `.test-streams/` and must
never be committed. Results (numbers only, no titles) go to `bench/results/`. Needs about 5x the input size of free disk in the
Docker volume (input, chunks, an `--in-place` copy, the output, a verification copy).

Per title the file can carry `extra_keys`: some files (PlayReady-style) have an all-zero KID in `tenc`; Flux resolves the real
KID itself, but Shaka and Bento4 only find the key if it is also given for the KID the file carries
(`00000000000000000000000000000000:<KEY>`). Bento4 additionally accepts a track-ID form (`1:<KEY>`).

## Notes and known gaps

* x86_64 only: the pinned Shaka and Bento4 binaries are x86_64 builds.
* The Shaka and Bento4 binaries are the upstream prebuilt ones, not rebuilt with the flags used for Flux.
* The three tools do not produce the same container (see the first table), so "whole file" compares workloads, not just
  cipher speed.
* Shaka Packager cannot read the PIFF `uuid` sample-encryption box used by the Smooth Streaming fragments
  (`IV cannot be empty`), so it has no result on that title.
* `flux IN -o -` (stdout for a single fragmented input) is described in the main README but the CLI only routes `-o -`
  through `--chunks`/`--in-place`; on a single input it asks for `-f`. It is benchmarked through `--chunks` only.
