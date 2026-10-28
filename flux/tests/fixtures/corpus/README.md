# Encrypted-file corpus

Small CENC files made by three independent encryptors from the same synthetic sources (ffmpeg `testsrc2` / `sine`, 2 s):

* `pkg_*`: Shaka Packager v3.9.3 (`--enable_raw_key_encryption`, single-file fMP4 with `sidx`, 1 s fragments)
* `b4_*`: Bento4 1.6.0-641 (`mp4fragment` + `mp4encrypt`)
* `gpac_*`: GPAC 2.2.1 (`MP4Box -crypt` + `-frag`)

`manifest.json` holds, per file, the key, the first `tfdt`, and `packet_md5`: the md5 of the clear packets as produced by
**Bento4's `mp4decrypt`** (`ffmpeg -c copy -f md5`), i.e. an oracle that is not flux; for the `gpac_*` files it is the md5 of the clear source packets. `wrong_key_refused` records whether a
wrong key is rejected up front; the HEVC files are `false` because the first-sample decode check cannot see a garbage
HEVC slice (libavcodec stays silent), so there a wrong key is only caught by decoding further.

Variants: cenc / cens / cbc1 / cbcs, 8- and 16-byte IVs, avc1 / hvc1 / hev1, AAC / AC-3 / E-AC-3, 64-bit `tfdt` (> 2^32),
no `sidx`, 1 s clear lead, a second KID.

The `gpac_*` files add what the other two cannot produce: 8-byte IVs, PIFF-style `uuid` boxes, IVs carried by `saiz`/`saio`,
cbcs HEVC, **key rotation** (`gpac_keyroll10_avc`: `seig` sample groups alternate between two KIDs, so the manifest lists
`extra_keys`) and a file with a video and an audio track under different keys (`gpac_av_twokeys`, `also` holds the audio md5).

`--fragments-info` (a segment cut out of the file) is not exercised on the `gpac_*` files: GPAC writes an absolute
`base_data_offset` into every `tfhd`, which cannot survive being cut into a standalone segment (flux refuses it with
"trun declares more bytes than the file actually has"). Packager and Bento4 use `default-base-is-moof`, like DASH segments.
`gpac_*` files also carry no `tfdt` at all; `--tfdt-rebase` must leave them without one.
