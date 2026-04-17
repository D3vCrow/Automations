"""Tests for tools/ffmpeg_studio.py — pure encoder/label helpers (Plan B / B4).

Covers the subprocess-free helpers:
    * _crf_label: CRF → quality-band label (incl. out-of-range fallback).
    * _guess_ratio: common aspect-ratio detection + h=0 guard + custom fallback.
    * _gpu_key_from_label / _codec_key_from_label / _chroma_depth_keys.
    * _pix_fmt: chroma × depth × GPU dispatch incl. NVENC 444+10-bit quirk.
    * _check_compat_warning: AMD AMF 4:4:4 unsupported table.
    * _build_video_codec_args: encoder selection + preset + pix-fmt tail.

Skipped here (need subprocess/FFmpeg mocking — out of scope for B4 smoke):
    _test_encoder, _probe_hardware, _detect_audio_devices.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools import ffmpeg_studio as fs  # noqa: E402


# ── _crf_label ───────────────────────────────────────────────────────

@pytest.mark.parametrize("val,expected", [
    (0,  "Near-Lossless  (huge files)"),
    (10, "Near-Lossless  (huge files)"),
    (11, "Excellent"),
    (18, "Excellent"),
    (19, "Good  \u2190 sweet spot"),
    (23, "Good  \u2190 sweet spot"),
    (26, "Balanced"),
    (33, "Balanced"),
    (34, "Small File"),
    (42, "Small File"),
    (43, "Low Quality"),
    (51, "Low Quality"),
])
def test_crf_label_bucket_boundaries(val, expected):
    assert fs._crf_label(val) == expected


def test_crf_label_out_of_range_returns_empty():
    assert fs._crf_label(-1) == ""
    assert fs._crf_label(52) == ""
    assert fs._crf_label(999) == ""


# ── _guess_ratio ─────────────────────────────────────────────────────

def test_guess_ratio_zero_height_is_safe():
    assert fs._guess_ratio(1920, 0) == "?"


@pytest.mark.parametrize("w,h,expected", [
    (1920, 1080, "16:9"),
    (3840, 2160, "16:9"),
    (1080, 1920, "9:16"),
    (1024, 768,  "4:3"),
    (600,  800,  "3:4"),
    (1000, 1000, "1:1"),
    (2560, 1080, "21:9"),
    (1080, 1350, "4:5"),
    (1500, 1200, "5:4"),
    (1500, 1000, "3:2"),
    (1000, 1500, "2:3"),
])
def test_guess_ratio_known_ratios(w, h, expected):
    assert fs._guess_ratio(w, h) == expected


def test_guess_ratio_uncommon_falls_back_to_custom():
    # 1234×456 ≈ 2.706 — not within 0.04 of any listed ratio.
    assert fs._guess_ratio(1234, 456) == "custom"


# ── _gpu_key_from_label ──────────────────────────────────────────────

@pytest.mark.parametrize("label,expected", [
    ("NVIDIA GPU  (NVENC)  — H.264 + H.265", "nvidia"),
    ("AMD GPU  (AMF)  — H.264 + H.265",      "amd"),
    ("Intel GPU  (QSV)",                     "intel"),
    ("CPU  (software)  — most compatible",   "cpu"),
    ("Some unknown label",                   "cpu"),
])
def test_gpu_key_from_label(label, expected):
    assert fs._gpu_key_from_label(label) == expected


# ── _codec_key_from_label ────────────────────────────────────────────

@pytest.mark.parametrize("label,expected", [
    ("H.264  (most compatible)",                   "h264"),
    ("H.265 / HEVC  (better quality, smaller files)", "h265"),
    ("AV1  (newest, smallest)",                    "av1"),
    ("Anything else",                              "h264"),
])
def test_codec_key_from_label(label, expected):
    assert fs._codec_key_from_label(label) == expected


# ── _chroma_depth_keys ───────────────────────────────────────────────

@pytest.mark.parametrize("chroma_label,depth_label,expected", [
    ("4:2:0  (standard — widest compatibility)", "8-bit",  ("420", "8")),
    ("4:2:2",                                     "10-bit", ("422", "10")),
    ("4:4:4",                                     "8-bit",  ("444", "8")),
    ("4:4:4",                                     "10-bit", ("444", "10")),
    # Numeric-only shorthand also recognized.
    ("422 sampling",                              "8",      ("422", "8")),
])
def test_chroma_depth_keys(chroma_label, depth_label, expected):
    assert fs._chroma_depth_keys(chroma_label, depth_label) == expected


# ── _pix_fmt ─────────────────────────────────────────────────────────

def test_pix_fmt_420_8bit_all_gpus():
    for gpu in ("nvidia", "amd", "intel", "cpu"):
        assert fs._pix_fmt("4:2:0", "8-bit", gpu) == "yuv420p"


def test_pix_fmt_420_10bit_gpus_use_p010():
    assert fs._pix_fmt("4:2:0", "10-bit", "nvidia") == "p010le"
    assert fs._pix_fmt("4:2:0", "10-bit", "amd") == "p010le"
    assert fs._pix_fmt("4:2:0", "10-bit", "intel") == "p010le"
    # CPU uses the sw fmt.
    assert fs._pix_fmt("4:2:0", "10-bit", "cpu") == "yuv420p10le"


def test_pix_fmt_444_10bit_nvenc_uses_16le_quirk():
    """NVENC HEVC 444+10-bit requires yuv444p16le, not yuv444p10le."""
    assert fs._pix_fmt("4:4:4", "10-bit", "nvidia") == "yuv444p16le"
    # AMD AMF falls back to p010le for 444+10-bit per the map.
    assert fs._pix_fmt("4:4:4", "10-bit", "amd") == "p010le"
    assert fs._pix_fmt("4:4:4", "10-bit", "cpu") == "yuv444p10le"


def test_pix_fmt_unknown_combo_falls_back_to_yuv420p():
    # Unknown depth → tuple defaults to ("yuv420p",)*4.
    assert fs._pix_fmt("4:2:0", "12-bit", "nvidia") == "yuv420p"


# ── _check_compat_warning ────────────────────────────────────────────

def test_check_compat_warning_amd_amf_444_rejected():
    warn = fs._check_compat_warning("amd", "h264", "4:4:4", "8-bit")
    assert warn is not None
    assert "4:4:4" in warn


def test_check_compat_warning_known_supported_returns_none():
    assert fs._check_compat_warning("nvidia", "h264", "4:2:0", "8-bit") is None
    assert fs._check_compat_warning("cpu", "h265", "4:4:4", "10-bit") is None


# ── _build_video_codec_args ──────────────────────────────────────────

def test_build_cpu_h264_uses_libx264_with_crf_and_preset():
    args = fs._build_video_codec_args(
        codec_key="h264", gpu_key="cpu", crf=23,
        speed_label="Fast", fmt="yuv420p",
    )
    assert args[:2] == ["-vcodec", "libx264"]
    assert "-crf" in args and args[args.index("-crf") + 1] == "23"
    assert "-preset" in args and args[args.index("-preset") + 1] == "fast"
    assert args[-2:] == ["-pix_fmt", "yuv420p"]


def test_build_cpu_av1_uses_libsvtav1_crf_only_no_preset():
    args = fs._build_video_codec_args(
        codec_key="av1", gpu_key="cpu", crf=30,
        speed_label="Medium", fmt="yuv420p",
    )
    assert args[:2] == ["-vcodec", "libsvtav1"]
    assert "-crf" in args
    # AV1 SVT path explicitly skips -preset.
    assert "-preset" not in args


def test_build_nvidia_h264_uses_vbr_cq_and_nvenc_preset():
    args = fs._build_video_codec_args(
        codec_key="h264", gpu_key="nvidia", crf=20,
        speed_label="Ultrafast", fmt="yuv420p",
    )
    assert args[:2] == ["-vcodec", "h264_nvenc"]
    assert "-rc:v" in args and args[args.index("-rc:v") + 1] == "vbr"
    assert "-cq:v" in args and args[args.index("-cq:v") + 1] == "20"
    # Ultrafast → NVENC preset p1.
    assert "-preset" in args and args[args.index("-preset") + 1] == "p1"


def test_build_amd_clamps_qp_to_0_51_and_uses_amf_quality():
    args = fs._build_video_codec_args(
        codec_key="h265", gpu_key="amd", crf=999,  # must clamp to 51
        speed_label="Medium", fmt="p010le",
    )
    assert args[:2] == ["-vcodec", "hevc_amf"]
    assert "-quality" in args and args[args.index("-quality") + 1] == "quality"
    assert args[args.index("-qp_i") + 1] == "51"
    assert args[args.index("-qp_p") + 1] == "51"


def test_build_intel_qsv_uses_global_quality():
    args = fs._build_video_codec_args(
        codec_key="h264", gpu_key="intel", crf=25,
        speed_label="Fast", fmt="yuv420p",
    )
    assert args[:2] == ["-vcodec", "h264_qsv"]
    assert args[args.index("-global_quality") + 1] == "25"
    # Fast → QSV preset 'fast'.
    assert args[args.index("-preset") + 1] == "fast"


def test_build_unknown_speed_falls_back_to_ultrafast_family():
    args = fs._build_video_codec_args(
        codec_key="h264", gpu_key="cpu", crf=23,
        speed_label="Turbo-Mystery", fmt="yuv420p",
    )
    # Unknown speed → SPEED_OPTIONS["Ultrafast"] → libx264 preset 'ultrafast'.
    assert args[args.index("-preset") + 1] == "ultrafast"


def test_build_unknown_gpu_falls_back_to_cpu_encoder():
    """ENCODER_MAP.get(codec_key, ...).get(gpu_key, cpu_encoder) fallback."""
    args = fs._build_video_codec_args(
        codec_key="h264", gpu_key="unknown-gpu", crf=23,
        speed_label="Fast", fmt="yuv420p",
    )
    # Unknown gpu falls through to the final 'else' (qsv branch in the
    # current implementation), but the encoder lookup returns libx264.
    assert args[1] == "libx264"
    assert args[-2:] == ["-pix_fmt", "yuv420p"]
