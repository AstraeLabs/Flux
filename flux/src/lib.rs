#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
extern crate alloc;

pub mod boxes;
pub mod codec;
#[cfg(feature = "cli")]
pub mod cli;
pub mod container;
pub mod crypto;
pub mod error;
pub mod ir;

pub use boxes::{
    bitreader, box_types, init_segment, movie_fragment, sample_entries, segments,
    subtitle_entries, timing, visual_ext,
};
pub use codec::{
    ac3, ac4, annexb, av1, avc_config, dts, flac, hevc_config, mp4esds, mpeg_legacy, mpegh,
    nalu_types, opus, sps, vp9, vvc_config,
};
pub use container::{media, pipeline, progressive, progressive_demux};
#[cfg(feature = "cenc")]
pub use container::webm_decrypt;
#[cfg(feature = "sample-aes")]
pub(crate) use container::ts_sample_aes;
#[cfg(feature = "sample-aes")]
pub(crate) use container::ts_bbts_decrypt;
pub use crypto::cenc;
#[cfg(feature = "cenc")]
pub use crypto::cenc_decrypt;
#[cfg(feature = "cenc")]
pub(crate) use crypto::cenc_crypto;
pub use crypto::drm;
#[cfg(feature = "sample-aes")]
pub use crypto::sample_aes;

pub use ac3::{Ac3SpecificBox, Ec3SpecificBox, Ec3Substream};
pub use ac4::{AC4_FOURCC, Ac4SpecificBox, DAC4_FOURCC};
pub use annexb::annexb_to_length_prefixed;
pub use av1::{AV01_FOURCC, AV1C_FOURCC, Av1ConfigurationBox, Av1SampleEntry};
pub use avc_config::{AVCConfigurationBox, AVCDecoderConfigurationRecord};
pub use box_types::{BoxHeader, BoxIter, BoxRef, BoxType, FullBoxHeader, box_iter, parse_box};
pub use cenc::{
    CencScheme, OriginalFormatBox, ProtectionSchemeInfoBox, ProtectionSystemSpecificHeaderBox,
    SENC_FLAG_USE_SUBSAMPLE_ENCRYPTION, SampleAuxInfoOffsetsBox, SampleAuxInfoSizesBox,
    SampleEncryptionBox, SampleEncryptionEntry, SchemeInformationBox, SchemeTypeBox,
    SubSampleEntry, TrackEncryptionBox,
};
#[cfg(feature = "cenc")]
pub use cenc_decrypt::{CencDecryptor, KeyMap};
pub use drm::{
    FAIRPLAY_SYSTEM_ID, PLAYREADY_SYSTEM_ID, WIDEVINE_SYSTEM_ID, cenc_kid_to_playready,
    fairplay_pssh, fairplay_pssh_data, playready_kid_to_cenc, playready_kid_value_decode,
    playready_pro, playready_pssh, playready_pssh_key_ids, playready_wrmheader, widevine_pssh,
    widevine_pssh_data, widevine_pssh_key_ids,
};
pub use dts::{
    DDTS_BODY_LEN, DDTS_FOURCC, DTSC_FOURCC, DTSE_FOURCC, DTSH_FOURCC, DTSL_FOURCC, DtsSpecificBox,
};
pub use error::{Error, Result};
pub use flac::{
    BLOCK_TYPE_STREAMINFO, DFLA_FOURCC, FLAC_FOURCC, FlacMetadataBlock, FlacSpecificBox,
};
pub use hevc_config::{HEVCConfigurationBox, HEVCDecoderConfigurationRecord};
pub use init_segment::{
    Ac3SampleEntry, Ac4SampleEntry, ChunkLargeOffsetBox, ChunkOffsetBox, DataEntryUrlBox,
    DataInformationBox, DataReferenceBox, DtsSampleEntry, Ec3SampleEntry, EditBox, FlacSampleEntry,
    HandlerBox, MediaBox, MediaHeaderBox, MediaInformationBox, MhaSampleEntry, MovieBox,
    MovieExtendsBox, MovieHeaderBox, Mp4aSampleEntry, OpaqueBox, OpusSampleEntry,
    SampleDescriptionBox, SampleEntryVariant, SampleSizeBox, SampleTableBox, SampleToChunkBox,
    SoundMediaHeaderBox, StblChild, StscEntry, SyncSampleBox, TrackBox, TrackExtendsBox,
    TrackHeaderBox, VideoMediaHeaderBox,
};
pub use media::{Fmp4Demux, Media, SkippedTrack, Track, TrackEncryption};
pub use movie_fragment::{
    MovieFragmentBox, MovieFragmentHeaderBox, TrackFragmentBaseMediaDecodeTimeBox,
    TrackFragmentBox, TrackFragmentHeaderBox, TrackFragmentRunBox, TrunSample,
};
pub use mp4esds::{
    DecoderConfigDescriptor, DecoderSpecificInfo, ESDescriptor, EsdsBox, ObjectTypeIndication,
    SLConfigDescriptor, StreamType,
};
pub use mpeg_legacy::{
    MPEG_AUDIO_SYNCWORD, Mpeg2SeqHeader, MpegAudioFrameHeader, MpegAudioLayer, SEQUENCE_HEADER_CODE,
};
pub use mpegh::{
    MHA1_FOURCC, MHA2_FOURCC, MHAC_CONFIGURATION_VERSION, MHAC_FOURCC, MHAC_RECORD_FIXED_LEN,
    MHADecoderConfigurationRecord, MHM1_FOURCC, MHM2_FOURCC,
};
pub use nalu_types::{AvcPps, AvcSps, AvcSpsExt, HevcNalArray, HevcNalUnit};
pub use opus::{ChannelMappingTable, DOPS_FOURCC, OPUS_FOURCC, OpusSpecificBox};
pub use pipeline::{
    CodecConfig, Provenance, Sample, SampleFlags, TrackSpec, build_init_segment,
};
pub use progressive::ProgressiveMux;
#[cfg(feature = "sample-aes")]
pub use sample_aes::{
    ExtXKey, HlsEncryptionMethod, aac_decrypt_frame, aac_encrypt_frame, ac3_decrypt_frame,
    ac3_encrypt_frame, aes128_decrypt_segment, aes128_encrypt_segment, h264_decrypt_nal,
    h264_encrypt_nal, iv_from_sequence_number,
};
pub use sample_entries::{
    AVCSampleEntry, HEVCSampleEntry, Mp4vSampleEntry, VisualSampleEntryFields,
};
pub use segments::FileTypeBox;
pub use subtitle_entries::{
    CueIdBox, CuePayloadBox, CueSettingsBox, VttCueBox, VttEmptyCueBox, WebVttConfigurationBox,
    WvttSampleEntry, XmlSubtitleSampleEntry,
};
pub use timing::{
    CompositionOffsetBox, CompositionToDecodeBox, CttsEntry, EditListBox, EditListEntry,
    SegmentIndexBox, SidxReference, SttsEntry, TimeToSampleBox,
};
pub use visual_ext::{CleanApertureBox, ColourInformationBox, NclxColourInfo, PixelAspectRatioBox};
pub use vp9::{VP09_FOURCC, VPCC_FOURCC, Vp9ConfigurationBox, Vp9SampleEntry};
pub use vvc_config::{
    VvcConfigurationBox, VvcDecoderConfigurationRecord, VvcNalArray, VvcNalUnitType, VvcPtlRecord,
};
