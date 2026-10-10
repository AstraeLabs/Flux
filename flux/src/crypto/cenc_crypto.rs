//! CENC cipher core

use aes::cipher::{Block, BlockDecryptMut, InnerIvInit, KeyInit, KeyIvInit, StreamCipher};
use alloc::vec::Vec;
use bytes::{Bytes, BytesMut};

use crate::cenc::{SampleEncryptionEntry, SubSampleEntry, TrackEncryptionBox};
use crate::error::{Error, Result};

pub(crate) fn rewrite_in_place(
    data: &mut Bytes,
    f: impl FnOnce(&mut [u8]) -> Result<()>,
) -> Result<bool> {
    let owned = core::mem::take(data);
    let (mut buf, fast_path) = match owned.try_into_mut() {
        Ok(buf) => (buf, true),
        Err(shared) => (BytesMut::from(&shared[..]), false),
    };
    let result = f(&mut buf);
    *data = buf.freeze();
    result.map(|()| fast_path)
}

fn validate_subsample_map(subsamples: &[SubSampleEntry], data_len: usize) -> Result<()> {
    let mut offset = 0usize;
    for sub in subsamples {
        offset = offset
            .checked_add(sub.bytes_of_clear_data as usize)
            .ok_or(Error::InvalidInput("CENC subsample clear length overflow"))?;
        let end = offset
            .checked_add(sub.bytes_of_protected_data as usize)
            .ok_or(Error::InvalidInput(
                "CENC subsample protected length overflow",
            ))?;
        if end > data_len {
            return Err(Error::BufferTooShort {
                need: end,
                have: data_len,
                what: "CENC subsample range exceeds sample",
            });
        }
        offset = end;
    }
    if offset != data_len {
        return Err(Error::InvalidInput(
            "CENC subsample map does not cover the whole sample (ISO/IEC 23001-7 §9.3): the \
             uncovered bytes would be passed through unprotected",
        ));
    }
    Ok(())
}

const VALID_IV_LENS: [usize; 2] = [8, 16];

fn check_iv_len(len: usize) -> Result<()> {
    if !VALID_IV_LENS.contains(&len) {
        return Err(Error::InvalidValue {
            field: "CENC IV length",
            value: len as u64,
            reason: "ISO/IEC 23001-7 §9.2/§12.2 permit only 8 or 16 bytes",
        });
    }
    Ok(())
}

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const KEY_LEN: usize = 16;

#[derive(Default)]
pub(crate) struct CbcScratch(Vec<Block<Aes128CbcDec>>);

pub(crate) fn apply_ctr(
    iv: &[u8],
    key: &[u8; KEY_LEN],
    subsamples: &[SubSampleEntry],
    data: &mut [u8],
) -> Result<()> {
    if iv.is_empty() {
        return Err(Error::InvalidInput(
            "cenc (AES-CTR) sample has no per-sample IV: an all-zero counter block would reuse \
             one keystream for every sample. cenc requires a per-sample IV in senc — a \
             tenc.default_constant_IV (default_per_sample_iv_size == 0) is cbcs-only",
        ));
    }
    check_iv_len(iv.len())?;
    if !subsamples.is_empty() {
        validate_subsample_map(subsamples, data.len())?;
    }

    let mut counter = [0u8; KEY_LEN];
    counter[..iv.len()].copy_from_slice(iv);

    let mut cipher = Aes128Ctr::new(key.into(), (&counter).into());

    if subsamples.is_empty() {
        cipher.apply_keystream(data);
        return Ok(());
    }

    let mut offset = 0usize;
    for sub in subsamples {
        offset += sub.bytes_of_clear_data as usize;
        let end = offset + sub.bytes_of_protected_data as usize;
        cipher.apply_keystream(&mut data[offset..end]);
        offset = end;
    }
    Ok(())
}

fn resolve_cbcs_iv(
    entry: &SampleEncryptionEntry,
    tenc: &TrackEncryptionBox,
) -> Result<[u8; KEY_LEN]> {
    let src: &[u8] = if !entry.initialization_vector.is_empty() {
        &entry.initialization_vector
    } else if let Some(civ) = tenc.default_constant_iv.as_deref() {
        civ
    } else {
        return Err(Error::InvalidInput(
            "cbcs sample has no per-sample IV and tenc carries no default_constant_IV",
        ));
    };
    check_iv_len(src.len())?;
    let mut iv = [0u8; KEY_LEN];
    iv[..src.len()].copy_from_slice(src);
    Ok(iv)
}

pub(crate) fn cbcs_pattern(
    block_cipher: &aes::Aes128,
    seed_iv: &[u8; KEY_LEN],
    crypt_byte_block: u8,
    skip_byte_block: u8,
    range: &mut [u8],
    scratch: &mut CbcScratch,
) {
    let (crypt_blocks, skip_blocks) = if crypt_byte_block == 0 && skip_byte_block == 0 {
        (1usize, 0usize)
    } else {
        (crypt_byte_block as usize, skip_byte_block as usize)
    };

    let mut dec = Aes128CbcDec::inner_iv_init(block_cipher.clone(), seed_iv.into());
    if skip_blocks == 0 {
        let run_len = (range.len() / KEY_LEN) * KEY_LEN;
        decrypt_blocks_in_place(&mut dec, &mut range[..run_len], scratch);
    } else {
        let mut offset = 0usize;
        while offset < range.len() {
            let remaining = range.len() - offset;
            let want = crypt_blocks * KEY_LEN;
            let run_len = (want.min(remaining) / KEY_LEN) * KEY_LEN;
            if run_len == 0 {
                break;
            }
            decrypt_blocks_in_place(&mut dec, &mut range[offset..offset + run_len], scratch);
            offset += run_len;
            if run_len < want {
                break;
            }
            offset += (skip_blocks * KEY_LEN).min(range.len() - offset);
        }
    }
}

fn decrypt_blocks_in_place(dec: &mut Aes128CbcDec, bytes: &mut [u8], scratch: &mut CbcScratch) {
    let blocks = &mut scratch.0;
    blocks.clear();
    blocks.extend(bytes.chunks_exact(KEY_LEN).map(Block::<Aes128CbcDec>::clone_from_slice));
    dec.decrypt_blocks_mut(blocks);
    for (dst, block) in bytes.chunks_exact_mut(KEY_LEN).zip(blocks.iter()) {
        dst.copy_from_slice(block);
    }
}

pub(crate) fn cbcs_sample(
    tenc: &TrackEncryptionBox,
    entry: &SampleEncryptionEntry,
    key: &[u8; KEY_LEN],
    data: &mut [u8],
    scratch: &mut CbcScratch,
) -> Result<()> {
    let crypt_blocks = tenc.default_crypt_byte_block;
    let skip_blocks = tenc.default_skip_byte_block;
    if crypt_blocks == 0 && skip_blocks != 0 {
        return Err(Error::InvalidInput(
            "cbcs pattern crypt_byte_block=0 with nonzero skip leaves data unprotected",
        ));
    }
    let seed_iv = resolve_cbcs_iv(entry, tenc)?;
    if !entry.subsamples.is_empty() {
        validate_subsample_map(&entry.subsamples, data.len())?;
    }

    let block_cipher = aes::Aes128::new(key.into());

    if entry.subsamples.is_empty() {
        cbcs_pattern(&block_cipher, &seed_iv, crypt_blocks, skip_blocks, data, scratch);
        return Ok(());
    }

    let mut offset = 0usize;
    for sub in &entry.subsamples {
        offset += sub.bytes_of_clear_data as usize;
        let end = offset + sub.bytes_of_protected_data as usize;
        cbcs_pattern(
            &block_cipher,
            &seed_iv,
            crypt_blocks,
            skip_blocks,
            &mut data[offset..end],
            scratch,
        );
        offset = end;
    }
    Ok(())
}

pub(crate) fn cbc1_sample(
    tenc: &TrackEncryptionBox,
    entry: &SampleEncryptionEntry,
    key: &[u8; KEY_LEN],
    data: &mut [u8],
    scratch: &mut CbcScratch,
) -> Result<()> {
    let seed_iv = resolve_cbcs_iv(entry, tenc)?;
    if !entry.subsamples.is_empty() {
        validate_subsample_map(&entry.subsamples, data.len())?;
    }

    let block_cipher = aes::Aes128::new(key.into());
    let mut dec = Aes128CbcDec::inner_iv_init(block_cipher, (&seed_iv).into());

    if entry.subsamples.is_empty() {
        let run_len = (data.len() / KEY_LEN) * KEY_LEN;
        decrypt_blocks_in_place(&mut dec, &mut data[..run_len], scratch);
        return Ok(());
    }

    let mut offset = 0usize;
    for sub in &entry.subsamples {
        offset += sub.bytes_of_clear_data as usize;
        let end = offset + sub.bytes_of_protected_data as usize;
        let run_len = ((end - offset) / KEY_LEN) * KEY_LEN;
        decrypt_blocks_in_place(&mut dec, &mut data[offset..offset + run_len], scratch);
        offset = end;
    }
    Ok(())
}

fn cens_pattern(cipher: &mut Aes128Ctr, crypt_byte_block: u8, skip_byte_block: u8, range: &mut [u8]) {
    let (crypt_blocks, skip_blocks) = if crypt_byte_block == 0 && skip_byte_block == 0 {
        (1usize, 0usize)
    } else {
        (crypt_byte_block as usize, skip_byte_block as usize)
    };

    if skip_blocks == 0 {
        cipher.apply_keystream(range);
        return;
    }

    let mut offset = 0usize;
    while offset < range.len() {
        let remaining = range.len() - offset;
        let run_len = (crypt_blocks * KEY_LEN).min(remaining);
        cipher.apply_keystream(&mut range[offset..offset + run_len]);
        offset += run_len;
        if run_len < crypt_blocks * KEY_LEN {
            break;
        }
        offset += (skip_blocks * KEY_LEN).min(range.len() - offset);
    }
}

pub(crate) fn cens_sample(
    tenc: &TrackEncryptionBox,
    entry: &SampleEncryptionEntry,
    key: &[u8; KEY_LEN],
    data: &mut [u8],
) -> Result<()> {
    if tenc.default_crypt_byte_block == 0 && tenc.default_skip_byte_block != 0 {
        return Err(Error::InvalidInput(
            "cens pattern crypt_byte_block=0 with nonzero skip leaves data unprotected",
        ));
    }
    if entry.initialization_vector.is_empty() {
        return Err(Error::InvalidInput(
            "cens (AES-CTR pattern) sample has no per-sample IV in senc — cens has no \
             default_constant_IV equivalent (that's cbcs-only)",
        ));
    }
    check_iv_len(entry.initialization_vector.len())?;
    if !entry.subsamples.is_empty() {
        validate_subsample_map(&entry.subsamples, data.len())?;
    }

    let mut counter = [0u8; KEY_LEN];
    counter[..entry.initialization_vector.len()].copy_from_slice(&entry.initialization_vector);
    let mut cipher = Aes128Ctr::new(key.into(), (&counter).into());

    let crypt_blocks = tenc.default_crypt_byte_block;
    let skip_blocks = tenc.default_skip_byte_block;

    if entry.subsamples.is_empty() {
        cens_pattern(&mut cipher, crypt_blocks, skip_blocks, data);
        return Ok(());
    }

    let mut offset = 0usize;
    for sub in &entry.subsamples {
        offset += sub.bytes_of_clear_data as usize;
        let end = offset + sub.bytes_of_protected_data as usize;
        cens_pattern(&mut cipher, crypt_blocks, skip_blocks, &mut data[offset..end]);
        offset = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncryptMut;

    fn tenc(crypt_byte_block: u8, skip_byte_block: u8, constant_iv: Option<[u8; KEY_LEN]>) -> TrackEncryptionBox {
        TrackEncryptionBox {
            version: 1,
            default_crypt_byte_block: crypt_byte_block,
            default_skip_byte_block: skip_byte_block,
            default_is_protected: 1,
            default_per_sample_iv_size: if constant_iv.is_some() { 0 } else { 8 },
            default_kid: [0u8; 16],
            default_constant_iv: constant_iv.map(|iv| iv.to_vec()),
        }
    }

    fn entry(iv: Vec<u8>, subsamples: Vec<SubSampleEntry>) -> SampleEncryptionEntry {
        SampleEncryptionEntry {
            initialization_vector: iv,
            subsamples,
            is_encrypted: true,
            explicit_kid: None,
        }
    }


    #[test]
    fn apply_ctr_matches_a_manually_built_ctr128be_keystream() {
        let key = [0x11u8; KEY_LEN];
        let iv = [0x22u8; 8];
        let plaintext = [0xAAu8; 40];
        let mut data = plaintext;
        apply_ctr(&iv, &key, &[], &mut data).unwrap();
        assert_ne!(data, plaintext);

        let mut counter = [0u8; KEY_LEN];
        counter[..8].copy_from_slice(&iv);
        let mut cipher = Aes128Ctr::new(&key.into(), &counter.into());
        let mut expected = plaintext;
        cipher.apply_keystream(&mut expected);
        assert_eq!(data, expected);
    }

    #[test]
    fn apply_ctr_is_its_own_inverse() {
        let key = [0x77u8; KEY_LEN];
        let iv = [0x88u8; 8];
        let original = [0x5Cu8; 33];
        let mut data = original;
        apply_ctr(&iv, &key, &[], &mut data).unwrap();
        apply_ctr(&iv, &key, &[], &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn apply_ctr_subsamples_leave_clear_runs_untouched_and_still_roundtrip() {
        let key = [0x33u8; KEY_LEN];
        let iv = [0x44u8; 8];
        let original: Vec<u8> = (0u8..64).collect();
        let mut data = original.clone();
        let subsamples = vec![
            SubSampleEntry { bytes_of_clear_data: 10, bytes_of_protected_data: 22 },
            SubSampleEntry { bytes_of_clear_data: 5, bytes_of_protected_data: 27 },
        ];
        apply_ctr(&iv, &key, &subsamples, &mut data).unwrap();
        assert_eq!(&data[0..10], &original[0..10], "first clear run must be untouched");
        assert_eq!(&data[32..37], &original[32..37], "second clear run must be untouched");
        assert_ne!(&data[10..32], &original[10..32]);
        assert_ne!(&data[37..64], &original[37..64]);

        apply_ctr(&iv, &key, &subsamples, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn apply_ctr_rejects_empty_iv() {
        let mut data = [0u8; 16];
        assert!(apply_ctr(&[], &[0u8; KEY_LEN], &[], &mut data).is_err());
    }

    #[test]
    fn apply_ctr_rejects_invalid_iv_length() {
        let mut data = [0u8; 16];
        assert!(apply_ctr(&[0u8; 4], &[0u8; KEY_LEN], &[], &mut data).is_err());
    }


    fn reference_cbc_pattern_encrypt(
        key: &[u8; KEY_LEN],
        seed_iv: &[u8; KEY_LEN],
        crypt_byte_block: u8,
        skip_byte_block: u8,
        data: &mut [u8],
    ) {
        let (crypt_blocks, skip_blocks) = if crypt_byte_block == 0 && skip_byte_block == 0 {
            (1usize, 0usize)
        } else {
            (crypt_byte_block as usize, skip_byte_block as usize)
        };
        let mut enc = cbc::Encryptor::<aes::Aes128>::new(key.into(), seed_iv.into());
        if skip_blocks == 0 {
            let run_len = (data.len() / KEY_LEN) * KEY_LEN;
            for block in data[..run_len].chunks_exact_mut(KEY_LEN) {
                enc.encrypt_block_mut(Block::<Aes128CbcDec>::from_mut_slice(block));
            }
            return;
        }
        let mut offset = 0usize;
        loop {
            let remaining = data.len() - offset;
            let want = crypt_blocks * KEY_LEN;
            let run_len = (want.min(remaining) / KEY_LEN) * KEY_LEN;
            if run_len == 0 {
                break;
            }
            for block in data[offset..offset + run_len].chunks_exact_mut(KEY_LEN) {
                enc.encrypt_block_mut(Block::<Aes128CbcDec>::from_mut_slice(block));
            }
            offset += run_len;
            if run_len < want || skip_blocks == 0 {
                break;
            }
            offset += (skip_blocks * KEY_LEN).min(data.len() - offset);
            if offset >= data.len() {
                break;
            }
        }
    }

    #[test]
    fn cbcs_sample_decrypts_a_1_9_pattern_reference_ciphertext() {
        let key = [0x05u8; KEY_LEN];
        let seed_iv = [0x06u8; KEY_LEN];
        let plaintext: Vec<u8> = (0u8..(16 * 15)).collect();
        let mut ciphertext = plaintext.clone();
        reference_cbc_pattern_encrypt(&key, &seed_iv, 1, 9, &mut ciphertext);
        assert_ne!(ciphertext, plaintext);

        let t = tenc(1, 9, Some(seed_iv));
        let e = entry(vec![], vec![]);
        let mut scratch = CbcScratch::default();
        cbcs_sample(&t, &e, &key, &mut ciphertext, &mut scratch).unwrap();
        assert_eq!(ciphertext, plaintext);
    }

    #[test]
    fn cbcs_sample_reseeds_iv_at_each_subsample_boundary() {
        let key = [0x09u8; KEY_LEN];
        let seed_iv = [0x0Au8; KEY_LEN];
        let plaintext: Vec<u8> = (0u8..32).collect();
        let mut ciphertext = plaintext.clone();
        reference_cbc_pattern_encrypt(&key, &seed_iv, 1, 0, &mut ciphertext[0..16]);
        reference_cbc_pattern_encrypt(&key, &seed_iv, 1, 0, &mut ciphertext[16..32]);

        let t = tenc(1, 0, Some(seed_iv));
        let e = entry(
            vec![],
            vec![
                SubSampleEntry { bytes_of_clear_data: 0, bytes_of_protected_data: 16 },
                SubSampleEntry { bytes_of_clear_data: 0, bytes_of_protected_data: 16 },
            ],
        );
        let mut scratch = CbcScratch::default();
        cbcs_sample(&t, &e, &key, &mut ciphertext, &mut scratch).unwrap();
        assert_eq!(ciphertext, plaintext);
    }

    #[test]
    fn cbc1_sample_chains_continuously_across_subsamples_without_reseeding() {
        let key = [0x0Bu8; KEY_LEN];
        let seed_iv = [0x0Cu8; KEY_LEN];
        let plaintext: Vec<u8> = (0u8..32).collect();
        let original_ciphertext = {
            let mut c = plaintext.clone();
            reference_cbc_pattern_encrypt(&key, &seed_iv, 1, 0, &mut c);
            c
        };

        let t = tenc(0, 0, Some(seed_iv));
        let e = entry(
            vec![],
            vec![
                SubSampleEntry { bytes_of_clear_data: 0, bytes_of_protected_data: 16 },
                SubSampleEntry { bytes_of_clear_data: 0, bytes_of_protected_data: 16 },
            ],
        );
        let mut scratch = CbcScratch::default();
        let mut ciphertext = original_ciphertext.clone();
        cbc1_sample(&t, &e, &key, &mut ciphertext, &mut scratch).unwrap();
        assert_eq!(ciphertext, plaintext);

        let mut as_cbcs = original_ciphertext;
        let t_cbcs = tenc(1, 0, Some(seed_iv));
        let e_cbcs = entry(
            vec![],
            vec![
                SubSampleEntry { bytes_of_clear_data: 0, bytes_of_protected_data: 16 },
                SubSampleEntry { bytes_of_clear_data: 0, bytes_of_protected_data: 16 },
            ],
        );
        cbcs_sample(&t_cbcs, &e_cbcs, &key, &mut as_cbcs, &mut scratch).unwrap();
        assert_ne!(as_cbcs, plaintext);
    }

    #[test]
    fn cens_sample_decrypts_a_pattern_encrypted_reference() {
        let key = [0x0Du8; KEY_LEN];
        let iv = [0x0Eu8; 8];
        let plaintext: Vec<u8> = (0u8..(16 * 6)).collect();
        let mut ciphertext = plaintext.clone();

        let mut counter = [0u8; KEY_LEN];
        counter[..8].copy_from_slice(&iv);
        let mut cipher = Aes128Ctr::new(&key.into(), &counter.into());
        let mut offset = 0usize;
        while offset < ciphertext.len() {
            cipher.apply_keystream(&mut ciphertext[offset..offset + KEY_LEN]);
            offset += 2 * KEY_LEN;
        }

        let t = tenc(1, 1, None);
        let e = entry(iv.to_vec(), vec![]);
        cens_sample(&t, &e, &key, &mut ciphertext).unwrap();
        assert_eq!(ciphertext, plaintext);
    }

    #[test]
    fn cbcs_sample_rejects_pattern_with_zero_crypt_and_nonzero_skip() {
        let key = [0u8; KEY_LEN];
        let t = tenc(0, 3, Some([0u8; KEY_LEN]));
        let e = entry(vec![], vec![]);
        let mut data = [0u8; 32];
        let mut scratch = CbcScratch::default();
        assert!(cbcs_sample(&t, &e, &key, &mut data, &mut scratch).is_err());
    }

    #[test]
    fn cens_rejects_zero_crypt_with_nonzero_skip() {
        let t = tenc(0, 9, None);
        let e = entry(vec![0u8; 8], vec![]);
        let mut data = [0u8; 64];
        assert!(cens_sample(&t, &e, &[0u8; KEY_LEN], &mut data).is_err());
    }
}
