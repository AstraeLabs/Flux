//! MPEG-H 3D Audio in ISOBMFF — `mha1`/`mhm1` + `mhaC` 

use crate::error::{Error, Result};
use alloc::vec::Vec;
use bitforge::{Parse, Serialize};

pub const MHAC_FOURCC: [u8; 4] = *b"mhaC";
pub const MHA1_FOURCC: [u8; 4] = *b"mha1";
pub const MHA2_FOURCC: [u8; 4] = *b"mha2";
pub const MHM1_FOURCC: [u8; 4] = *b"mhm1";
pub const MHM2_FOURCC: [u8; 4] = *b"mhm2";

pub const MHAC_RECORD_FIXED_LEN: usize = 5;

pub const MHAC_CONFIGURATION_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MHADecoderConfigurationRecord {
    pub configuration_version: u8,
    pub mpegh3da_profile_level_indication: u8,
    pub reference_channel_layout: u8,
    pub mpegh3da_config: Vec<u8>,
}

impl MHADecoderConfigurationRecord {
    pub fn new(
        mpegh3da_profile_level_indication: u8,
        reference_channel_layout: u8,
        mpegh3da_config: Vec<u8>,
    ) -> Self {
        Self {
            configuration_version: MHAC_CONFIGURATION_VERSION,
            mpegh3da_profile_level_indication,
            reference_channel_layout,
            mpegh3da_config,
        }
    }
}

impl<'a> Parse<'a> for MHADecoderConfigurationRecord {
    type Error = Error;

    fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < MHAC_RECORD_FIXED_LEN {
            return Err(Error::BufferTooShort {
                need: MHAC_RECORD_FIXED_LEN,
                have: bytes.len(),
                what: "MHADecoderConfigurationRecord",
            });
        }
        let configuration_version = bytes[0];
        if configuration_version != MHAC_CONFIGURATION_VERSION {
            return Err(Error::InvalidValue {
                field: "configurationVersion",
                value: configuration_version as u64,
                reason: "must be 1 (ISO/IEC 23008-3 §20)",
            });
        }
        let mpegh3da_profile_level_indication = bytes[1];
        let reference_channel_layout = bytes[2];
        let config_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        let need = MHAC_RECORD_FIXED_LEN + config_len;
        if bytes.len() < need {
            return Err(Error::BufferTooShort {
                need,
                have: bytes.len(),
                what: "MHADecoderConfigurationRecord.mpegh3daConfig",
            });
        }
        let mpegh3da_config = bytes[MHAC_RECORD_FIXED_LEN..need].to_vec();
        Ok(Self {
            configuration_version,
            mpegh3da_profile_level_indication,
            reference_channel_layout,
            mpegh3da_config,
        })
    }
}

impl Serialize for MHADecoderConfigurationRecord {
    type Error = Error;

    fn serialized_len(&self) -> usize {
        MHAC_RECORD_FIXED_LEN + self.mpegh3da_config.len()
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        let need = self.serialized_len();
        if buf.len() < need {
            return Err(Error::OutputBufferTooSmall {
                need,
                have: buf.len(),
            });
        }
        buf[0] = self.configuration_version;
        buf[1] = self.mpegh3da_profile_level_indication;
        buf[2] = self.reference_channel_layout;
        let config_len = self.mpegh3da_config.len() as u16;
        buf[3..5].copy_from_slice(&config_len.to_be_bytes());
        buf[5..need].copy_from_slice(&self.mpegh3da_config);
        Ok(need)
    }
}

pub type MhaCBox = MHADecoderConfigurationRecord;
