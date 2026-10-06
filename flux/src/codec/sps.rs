//! H.264 / H.265 sequence parameter set (SPS) decode.

use crate::bitreader::BitReader;
use crate::error::{Error, Result};

const H264_HIGH_PROFILES: &[u8] = &[100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135];

pub(crate) fn is_high_profile(profile_idc: u8) -> bool {
    H264_HIGH_PROFILES.contains(&profile_idc)
}

fn avc_sub_width_c(chroma_format_idc: u8) -> u32 {
    match chroma_format_idc {
        0 => 1,
        1 => 2,
        2 => 2,
        _ => 1,
    }
}

fn avc_sub_height_c(chroma_format_idc: u8) -> u32 {
    match chroma_format_idc {
        0 => 1,
        1 => 2,
        2 => 1,
        _ => 1,
    }
}

pub struct AvcSpsInfo {
    pub width: u32,
    pub height: u32,
}

pub fn decode_avc_sps(sps_bytes: &[u8]) -> Result<AvcSpsInfo> {
    if sps_bytes.len() < 4 {
        return Err(Error::BufferTooShort {
            need: 4,
            have: sps_bytes.len(),
            what: "H.264 SPS header",
        });
    }

    let profile_idc = sps_bytes[1];

    let mut r = BitReader::with_unescape(&sps_bytes[4..], "H.264 SPS")?;

    let _sps_id = r.read_ue("seq_parameter_set_id")?;

    let chroma_format_idc = if is_high_profile(profile_idc) {
        let chroma_format_idc = r.read_ue("chroma_format_idc")? as u8;
        if chroma_format_idc == 3 {
            let _ = r.read_flag("separate_colour_plane_flag")?;
        }
        let _bit_depth_luma_minus8 = r.read_ue("bit_depth_luma_minus8")?;
        let _bit_depth_chroma_minus8 = r.read_ue("bit_depth_chroma_minus8")?;
        let _ = r.read_flag("qpprime_y_zero_transform_bypass_flag")?;
        let scaling_matrix_present = r.read_flag("seq_scaling_matrix_present_flag")?;
        if scaling_matrix_present {
            let list_count = if chroma_format_idc != 3 { 8 } else { 12 };
            for _i in 0..list_count {
                let list_present = r.read_flag("seq_scaling_list_present_flag[i]")?;
                if list_present {
                    let size: usize = if _i < 6 { 16 } else { 64 };
                    let mut last_scale: i64 = 8;
                    let mut next_scale: i64 = 8;
                    for _j in 0..size {
                        if next_scale != 0 {
                            let delta_scale = r.read_se("delta_scale")?;
                            next_scale = (last_scale + delta_scale + 256) % 256;
                        }
                        if next_scale != 0 {
                            last_scale = next_scale;
                        }
                    }
                }
            }
        }
        chroma_format_idc
    } else {
        1
    };

    let _ = r.read_ue("log2_max_frame_num_minus4")?;
    let pic_order_cnt_type = r.read_ue("pic_order_cnt_type")?;
    if pic_order_cnt_type == 0 {
        let _ = r.read_ue("log2_max_pic_order_cnt_lsb_minus4")?;
    } else if pic_order_cnt_type == 1 {
        let _ = r.read_flag("delta_pic_order_always_zero_flag")?;
        let _ = r.read_se("offset_for_non_ref_pic")?;
        let _ = r.read_se("offset_for_top_to_bottom_field")?;
        let num_ref_frames = r.read_ue("num_ref_frames_in_pic_order_cnt_cycle")?;
        for _ in 0..num_ref_frames {
            let _ = r.read_se("offset_for_ref_frame[i]")?;
        }
    }
    let _ = r.read_ue("max_num_ref_frames")?;
    let _ = r.read_flag("gaps_in_frame_num_value_allowed_flag")?;
    let pic_width_in_mbs_minus1 = r.read_ue("pic_width_in_mbs_minus1")?;
    let pic_height_in_map_units_minus1 = r.read_ue("pic_height_in_map_units_minus1")?;
    let frame_mbs_only = r.read_flag("frame_mbs_only_flag")?;

    if !frame_mbs_only {
        let _ = r.read_flag("mb_adaptive_frame_field_flag")?;
    }

    let _ = r.read_flag("direct_8x8_inference_flag")?;
    let frame_cropping = r.read_flag("frame_cropping_flag")?;

    let (crop_left, crop_right, crop_top, crop_bottom) = if frame_cropping {
        let cl = r.read_ue("frame_crop_left_offset")?;
        let cr = r.read_ue("frame_crop_right_offset")?;
        let ct = r.read_ue("frame_crop_top_offset")?;
        let cb = r.read_ue("frame_crop_bottom_offset")?;
        (cl, cr, ct, cb)
    } else {
        (0, 0, 0, 0)
    };

    let pic_width_in_mbs = pic_width_in_mbs_minus1 + 1;
    let pic_height_in_map_units = pic_height_in_map_units_minus1 + 1;
    let frame_height_in_mbs = (2 - frame_mbs_only as u64) * pic_height_in_map_units;

    let crop_unit_x = avc_sub_width_c(chroma_format_idc) as u64;
    let crop_unit_y = avc_sub_height_c(chroma_format_idc) as u64 * (2 - frame_mbs_only as u64);

    let width = (pic_width_in_mbs * 16).saturating_sub(crop_unit_x * (crop_left + crop_right));
    let height = (frame_height_in_mbs * 16).saturating_sub(crop_unit_y * (crop_top + crop_bottom));

    Ok(AvcSpsInfo {
        width: width as u32,
        height: height as u32,
    })
}

pub struct HevcSpsInfo {
    pub width: u32,
    pub height: u32,
}

pub fn decode_hevc_sps(sps_bytes: &[u8]) -> Result<HevcSpsInfo> {
    if sps_bytes.len() < 2 {
        return Err(Error::BufferTooShort {
            need: 2,
            have: sps_bytes.len(),
            what: "HEVC SPS header",
        });
    }

    let mut r = BitReader::with_unescape(&sps_bytes[2..], "HEVC SPS")?;

    let _ = r.read_bits(4, "sps_video_parameter_set_id")?;
    let sps_max_sub_layers_minus1 = r.read_bits(3, "sps_max_sub_layers_minus1")? as u8;
    let _ = r.read_flag("sps_temporal_id_nesting_flag")?;

    hevc_skip_ptl(&mut r, true, sps_max_sub_layers_minus1)?;

    let _ = r.read_ue("sps_seq_parameter_set_id")?;
    let chroma_format_idc = r.read_ue("chroma_format_idc")? as u8;
    if chroma_format_idc == 3 {
        let _ = r.read_flag("separate_colour_plane_flag")?;
    }
    let pic_width_in_luma_samples = r.read_ue("pic_width_in_luma_samples")?;
    let pic_height_in_luma_samples = r.read_ue("pic_height_in_luma_samples")?;
    let conformance_window = r.read_flag("conformance_window_flag")?;
    let (conf_win_left, conf_win_right, conf_win_top, conf_win_bottom) = if conformance_window {
        let left = r.read_ue("conf_win_left_offset")?;
        let right = r.read_ue("conf_win_right_offset")?;
        let top = r.read_ue("conf_win_top_offset")?;
        let bottom = r.read_ue("conf_win_bottom_offset")?;
        (left, right, top, bottom)
    } else {
        (0, 0, 0, 0)
    };

    let sub_width_c = match chroma_format_idc {
        1 | 2 => 2,
        3 => 1,
        _ => 1,
    };
    let sub_height_c = match chroma_format_idc {
        1 => 2,
        2 | 3 => 1,
        _ => 1,
    };

    let width = pic_width_in_luma_samples
        .saturating_sub((sub_width_c as u64) * (conf_win_left + conf_win_right));
    let height = pic_height_in_luma_samples
        .saturating_sub((sub_height_c as u64) * (conf_win_top + conf_win_bottom));

    Ok(HevcSpsInfo {
        width: width as u32,
        height: height as u32,
    })
}

fn hevc_skip_ptl(
    r: &mut BitReader,
    profile_present_flag: bool,
    max_sub_layers_minus1: u8,
) -> Result<()> {
    if profile_present_flag {
        let _ = r.read_bits(2, "general_profile_space")?;
        let _ = r.read_flag("general_tier_flag")?;
        let _ = r.read_bits(5, "general_profile_idc")?;
    }

    let _ = r.read_bits(32, "general_profile_compatibility_flags")?;
    let _ = r.read_bits(48, "general_constraint_indicator_flags")?;
    let _ = r.read_bits(8, "general_level_idc")?;

    let mut sub_layer_profile_present_flag = [false; 7];
    let mut sub_layer_level_present_flag = [false; 7];
    for i in 0..max_sub_layers_minus1 {
        sub_layer_profile_present_flag[i as usize] =
            r.read_flag("sub_layer_profile_present_flag[i]")?;
        sub_layer_level_present_flag[i as usize] =
            r.read_flag("sub_layer_level_present_flag[i]")?;
    }

    if max_sub_layers_minus1 > 0 {
        for _i in max_sub_layers_minus1..8 {
            let _ = r.read_bits(2, "reserved_zero_2bits")?;
        }
    }

    for i in 0..max_sub_layers_minus1 {
        if sub_layer_profile_present_flag[i as usize] {
            let _ = r.read_bits(2, "sub_layer_profile_space")?;
            let _ = r.read_flag("sub_layer_tier_flag")?;
            let _ = r.read_bits(5, "sub_layer_profile_idc")?;
            let _ = r.read_bits(32, "sub_layer_profile_compatibility_flags")?;
            let _ = r.read_bits(48, "sub_layer_constraint_indicator_flags")?;
        }
        if sub_layer_level_present_flag[i as usize] {
            let _ = r.read_bits(8, "sub_layer_level_idc")?;
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VvcSpsInfo {
    pub chroma_format_idc: u8,
    pub general_profile_idc: u8,
    pub general_tier_flag: bool,
    pub general_level_idc: u8,
    pub width: u32,
    pub height: u32,
}

pub fn decode_vvc_sps(sps_bytes: &[u8]) -> Result<VvcSpsInfo> {
    if sps_bytes.len() < 2 {
        return Err(Error::BufferTooShort {
            need: 2,
            have: sps_bytes.len(),
            what: "VVC SPS header",
        });
    }

    let mut r = BitReader::with_unescape(&sps_bytes[2..], "VVC SPS")?;

    let _ = r.read_bits(4, "sps_seq_parameter_set_id")?;
    let _ = r.read_bits(4, "sps_video_parameter_set_id")?;
    let sps_max_sublayers_minus1 = r.read_bits(3, "sps_max_sublayers_minus1")? as u8;
    let chroma_format_idc = r.read_bits(2, "sps_chroma_format_idc")? as u8;
    let _ = r.read_bits(2, "sps_log2_ctu_size_minus5")?;
    let ptl_present = r.read_flag("sps_ptl_dpb_hrd_params_present_flag")?;

    let (general_profile_idc, general_tier_flag, general_level_idc) = if ptl_present {
        decode_vvc_ptl(&mut r, sps_max_sublayers_minus1)?
    } else {
        (0, false, 0)
    };

    let _ = r.read_flag("sps_gdr_enabled_flag")?;
    let ref_pic_resampling = r.read_flag("sps_ref_pic_resampling_enabled_flag")?;
    if ref_pic_resampling {
        let _ = r.read_flag("sps_res_change_in_clvs_allowed_flag")?;
    }
    let width = r.read_ue("sps_pic_width_max_in_luma_samples")?;
    let height = r.read_ue("sps_pic_height_max_in_luma_samples")?;

    Ok(VvcSpsInfo {
        chroma_format_idc,
        general_profile_idc,
        general_tier_flag,
        general_level_idc,
        width: width as u32,
        height: height as u32,
    })
}

fn decode_vvc_ptl(r: &mut BitReader, max_sublayers_minus1: u8) -> Result<(u8, bool, u8)> {
    let general_profile_idc = r.read_bits(7, "general_profile_idc")? as u8;
    let general_tier_flag = r.read_flag("general_tier_flag")?;
    let general_level_idc = r.read_bits(8, "general_level_idc")? as u8;
    let _ = r.read_flag("ptl_frame_only_constraint_flag")?;
    let _ = r.read_flag("ptl_multilayer_enabled_flag")?;

    let gci_present = r.read_flag("gci_present_flag")?;
    if gci_present {
        let _ = r.read_flag("gci_intra_only_constraint_flag")?;
        let _ = r.read_flag("gci_all_layers_independent_constraint_flag")?;
        let _ = r.read_flag("gci_one_au_only_constraint_flag")?;
        let _ = r.read_bits(4, "gci_sixteen_minus_max_bitdepth_constraint_idc")?;
        let _ = r.read_bits(2, "gci_three_minus_max_chroma_format_constraint_idc")?;
        for _ in 0..10 {
            let _ = r.read_flag("gci_nal_unit_type_constraint_flag")?;
        }
        for _ in 0..6 {
            let _ = r.read_flag("gci_partitioning_constraint_flag")?;
        }
        let _ = r.read_bits(2, "gci_three_minus_max_log2_ctu_size_constraint_idc")?;
        for _ in 0..3 {
            let _ = r.read_flag("gci_ctu_partitioning_constraint_flag")?;
        }
        for _ in 0..6 {
            let _ = r.read_flag("gci_intra_constraint_flag")?;
        }
        for _ in 0..16 {
            let _ = r.read_flag("gci_inter_constraint_flag")?;
        }
        for _ in 0..13 {
            let _ = r.read_flag("gci_transform_constraint_flag")?;
        }
        for _ in 0..6 {
            let _ = r.read_flag("gci_loop_filter_constraint_flag")?;
        }

        let num_additional_bits = r.read_bits(8, "gci_num_additional_bits")?;
        let num_additional_bits_used = if num_additional_bits > 5 {
            for _ in 0..6 {
                let _ = r.read_flag("gci_additional_constraint_flag")?;
            }
            6
        } else {
            0
        };
        for _ in 0..(num_additional_bits - num_additional_bits_used) {
            let _ = r.read_flag("gci_reserved_bit")?;
        }
    }
    r.align_to_byte("gci_alignment_zero_bit")?;

    let mut sublayer_present = [false; 8];
    for i in (0..max_sublayers_minus1).rev() {
        sublayer_present[i as usize] = r.read_flag("ptl_sublayer_level_present_flag[i]")?;
    }
    if max_sublayers_minus1 > 0 {
        r.align_to_byte("ptl_reserved_zero_bit")?;
    }
    for i in (0..max_sublayers_minus1).rev() {
        if sublayer_present[i as usize] {
            let _ = r.read_bits(8, "sublayer_level_idc[i]")?;
        }
    }
    let num_sub_profiles = r.read_bits(8, "ptl_num_sub_profiles")?;
    for _ in 0..num_sub_profiles {
        let _ = r.read_bits(32, "general_sub_profile_idc[j]")?;
    }

    Ok((general_profile_idc, general_tier_flag, general_level_idc))
}
