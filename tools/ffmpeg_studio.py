"""
ffmpeg_studio.py

FFmpeg Studio – Gameplay Recorder & Video Converter
- Record your screen/gameplay using FFmpeg
- Hardware GPU encoding (NVIDIA, AMD, Intel) auto-detected
- Presets for common use cases
- Convert videos between formats
"""

import os
import re
import subprocess
import tempfile
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext

import customtkinter as ctk

from tools._common.config import get_path
from tools._common.exceptions import narrow_excepts
from tools._common.logging import get_logger

TOOL_NAME = "FFmpeg Studio"
TOOL_DESC = "Record gameplay and convert videos using FFmpeg"
log = get_logger(__name__)

# ── Presets ───────────────────────────────────────────────────────────────────
PRESETS = {
    "Max Quality": {
        "fps": 60, "crf": 16, "speed": "Fast",
        "resolution": "Native (your screen)",
        "codec": "H.264  (most compatible)",
        "color_range": "Full Range  (recommended for PC / Gaming)",
        "chroma": "4:2:0  (standard — widest compatibility)",
        "bit_depth": "8-bit",
        "audio": True,
        "hint": "Best quality with H.264 — works on all GPU drivers. For 10-bit encoding switch to H.265 (requires NVIDIA driver 570+ / AMD equivalent), or use CPU encoder.",
    },
    "Balanced": {
        "fps": 60, "crf": 23, "speed": "Ultrafast",
        "resolution": "Native (your screen)",
        "codec": "H.264  (most compatible)",
        "color_range": "Full Range  (recommended for PC / Gaming)",
        "chroma": "4:2:0  (standard — widest compatibility)",
        "bit_depth": "8-bit",
        "audio": True,
        "hint": "Great quality, reasonable file size. Best choice for most gameplay recordings.",
    },
    "Streaming Ready": {
        "fps": 30, "crf": 28, "speed": "Ultrafast",
        "resolution": "1080p (1920×1080)",
        "codec": "H.264  (most compatible)",
        "color_range": "Limited Range  (broadcast / YouTube standard)",
        "chroma": "4:2:0  (standard — widest compatibility)",
        "bit_depth": "8-bit",
        "audio": True,
        "hint": "Smaller files, optimised for quick uploads or sharing. 30fps, 1080p.",
    },
    "Storage Saver": {
        "fps": 30, "crf": 35, "speed": "Ultrafast",
        "resolution": "720p (1280×720)",
        "codec": "H.265 / HEVC  (better quality, smaller files)",
        "color_range": "Full Range  (recommended for PC / Gaming)",
        "chroma": "4:2:0  (standard — widest compatibility)",
        "bit_depth": "8-bit",
        "audio": False,
        "hint": "Minimum file size for long sessions. Quality is reduced but playable.",
    },
}

RESOLUTIONS = {
    "Native (your screen)": None,
    "4K (3840×2160)":       "3840:2160",
    "1440p (2560×1440)":    "2560:1440",
    "1080p (1920×1080)":    "1920:1080",
    "720p (1280×720)":      "1280:720",
}

SPEED_OPTIONS = {
    # label → (x264/x265_preset, nvenc_preset, amf_quality, qsv_preset)
    "Ultrafast": ("ultrafast", "p1", "speed",   "veryfast"),
    "Fast":      ("fast",      "p3", "balanced", "fast"),
    "Medium":    ("medium",    "p5", "quality",  "medium"),
}

# Codec → GPU preference → encoder string
ENCODER_MAP = {
    "h264": {"nvidia": "h264_nvenc",  "amd": "h264_amf",  "intel": "h264_qsv",  "cpu": "libx264"},
    "h265": {"nvidia": "hevc_nvenc",  "amd": "hevc_amf",  "intel": "hevc_qsv",  "cpu": "libx265"},
    "av1":  {"nvidia": "av1_nvenc",   "amd": "av1_amf",   "intel": "av1_qsv",   "cpu": "libsvtav1"},
}

# Chroma + bit-depth → pixel format per encoder family
# (chroma_key, depth_key) → (sw_fmt, nvenc_fmt, amf_fmt, qsv_fmt)
# NVENC HEVC 444+10-bit requires yuv444p16le (not yuv444p10le)
# AMD AMF does not support 4:2:2 or 4:4:4 → silently falls back to 4:2:0
PIX_FMT_MAP = {
    ("420", "8"):  ("yuv420p",     "yuv420p",  "yuv420p",  "yuv420p"),
    ("420", "10"): ("yuv420p10le", "p010le",   "p010le",   "p010le"),
    ("422", "8"):  ("yuv422p",     "yuv422p",  "yuv422p",  "yuv422p"),
    ("422", "10"): ("yuv422p10le", "yuv422p10le", "yuv422p10le", "yuv422p10le"),
    ("444", "8"):  ("yuv444p",     "yuv444p",  "yuv444p",  "yuv444p"),
    # NVENC HEVC needs yuv444p16le for 10-bit 4:4:4; AMF falls back to p010le
    ("444", "10"): ("yuv444p10le", "yuv444p16le", "p010le", "yuv444p10le"),
}

# Combinations that are known to be unsupported and will silently fail
# (gpu_key, codec_key, chroma, depth): user-friendly warning
_UNSUPPORTED = {
    # AMD AMF: no 4:4:4 for any codec
    ("amd", "h264", "444", "8"):  "AMD AMF H.264 does not support 4:4:4. Switch to 4:2:0.",
    ("amd", "h264", "444", "10"): "AMD AMF H.264 does not support 4:4:4. Switch to 4:2:0.",
    ("amd", "h265", "444", "8"):  "AMD AMF H.265 does not support 4:4:4. Switch to 4:2:0.",
    ("amd", "h265", "444", "10"): "AMD AMF H.265 does not support 4:4:4. Switch to 4:2:0.",
    ("amd", "av1",  "444", "8"):  "AMD AMF AV1 does not support 4:4:4. Switch to 4:2:0.",
    ("amd", "av1",  "444", "10"): "AMD AMF AV1 does not support 4:4:4. Switch to 4:2:0.",
}

# Combinations that are FATAL (will always produce a 0-byte file) and must be
# auto-fixed before recording. Value = (fix description, var_name, new_value)
# These are never offered a "try anyway" option.
_FATAL_CONFLICTS = {
    # H.264 GPU encoders (all vendors) only support 8-bit.
    # 10-bit with H.264 requires the CPU encoder (libx264).
    ("nvidia", "h264", "420", "10"): "H.264 NVENC does not support 10-bit. Switched to 8-bit automatically.\nTo use 10-bit, select H.265 or CPU encoder.",
    ("nvidia", "h264", "422", "10"): "H.264 NVENC does not support 10-bit. Switched to 8-bit automatically.\nTo use 10-bit, select H.265 or CPU encoder.",
    ("nvidia", "h264", "444", "10"): "H.264 NVENC does not support 10-bit. Switched to 8-bit automatically.\nTo use 10-bit, select H.265 or CPU encoder.",
    ("amd",    "h264", "420", "10"): "H.264 AMF does not support 10-bit. Switched to 8-bit automatically.\nTo use 10-bit, select H.265 or CPU encoder.",
    ("amd",    "h264", "422", "10"): "H.264 AMF does not support 10-bit. Switched to 8-bit automatically.\nTo use 10-bit, select H.265 or CPU encoder.",
    ("intel",  "h264", "420", "10"): "H.264 QSV does not support 10-bit. Switched to 8-bit automatically.\nTo use 10-bit, select H.265 or CPU encoder.",
    ("intel",  "h264", "422", "10"): "H.264 QSV does not support 10-bit. Switched to 8-bit automatically.\nTo use 10-bit, select H.265 or CPU encoder.",
}

CRF_LABELS = [
    (0,  10, "Near-Lossless  (huge files)"),
    (11, 18, "Excellent"),
    (19, 25, "Good  ← sweet spot"),
    (26, 33, "Balanced"),
    (34, 42, "Small File"),
    (43, 51, "Low Quality"),
]

def _crf_label(val):
    for lo, hi, label in CRF_LABELS:
        if lo <= val <= hi:
            return label
    return ""

def _guess_ratio(w, h):
    """Return a common aspect-ratio name or 'custom'."""
    if h == 0:
        return "?"
    r = w / h
    for ratio, name in [
        (16/9,  "16:9"),   (9/16,  "9:16"),
        (4/3,   "4:3"),    (3/4,   "3:4"),
        (1/1,   "1:1"),    (21/9,  "21:9"),
        (4/5,   "4:5"),    (5/4,   "5:4"),
        (3/2,   "3:2"),    (2/3,   "2:3"),
    ]:
        if abs(r - ratio) < 0.04:
            return name
    return "custom"

# Preset crop regions — (label, w, h, description)
CROP_PRESETS = [
    ("1920×1080",  1920, 1080, "16:9  HD"),
    ("2560×1440",  2560, 1440, "16:9  2K"),
    ("3840×2160",  3840, 2160, "16:9  4K"),
    ("1280×720",   1280,  720, "16:9  720p"),
    ("1080×1920",  1080, 1920, "9:16  Shorts / TikTok / Reels"),
    ("1080×1080",  1080, 1080, "1:1   Instagram square"),
    ("1080×1350",  1080, 1350, "4:5   Instagram portrait"),
    ("1080×608",   1080,  608, "16:9  small social"),
]

# ── FFmpeg capability detection ───────────────────────────────────────────────
@narrow_excepts(
    OSError, subprocess.SubprocessError, subprocess.TimeoutExpired,
    default=False,
)
def _test_encoder(encoder_name, pix_fmt="yuv420p"):
    """Actually run a 0.1-second dummy encode to confirm the encoder works.

    Returns ``False`` on any subprocess/OS failure (caught by the
    decorator) so capability probes never raise into the UI thread.
    """
    r = subprocess.run(
        ["ffmpeg", "-f", "lavfi", "-i", "nullsrc=s=320x240",
         "-t", "0.1", "-vcodec", encoder_name,
         "-pix_fmt", pix_fmt, "-f", "null", "-"],
        capture_output=True, timeout=10,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    return r.returncode == 0

def _probe_hardware():
    """
    Test every encoder that FFmpeg lists and return:
      gpu_options  – ordered list of label strings for the dropdown
      gpu_label_to_key – maps label → gpu_key ("nvidia"/"amd"/"intel"/"cpu")
      hevc_ok      – set of gpu_keys whose H.265 encoder actually works
      best_gpu_key – gpu_key of the first working GPU encoder (or "cpu")
    """
    try:
        r = subprocess.run(["ffmpeg", "-encoders"], capture_output=True, text=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        listed = r.stdout + r.stderr
    except (OSError, subprocess.SubprocessError):
        listed = ""

    gpu_options      = []
    gpu_label_to_key = {}
    hevc_ok          = set()
    best_gpu_key     = "cpu"

    # NVIDIA
    if "h264_nvenc" in listed and _test_encoder("h264_nvenc"):
        h265_works = "hevc_nvenc" in listed and _test_encoder("hevc_nvenc")
        if h265_works:
            hevc_ok.add("nvidia")
            label = "NVIDIA GPU  (NVENC)  — H.264 + H.265"
        else:
            label = "NVIDIA GPU  (NVENC)  — H.264 only  ⚠ update driver for H.265"
        gpu_options.append(label)
        gpu_label_to_key[label] = "nvidia"
        if best_gpu_key == "cpu":
            best_gpu_key = "nvidia"

    # AMD
    if "h264_amf" in listed and _test_encoder("h264_amf"):
        h265_works = "hevc_amf" in listed and _test_encoder("hevc_amf")
        if h265_works:
            hevc_ok.add("amd")
            label = "AMD GPU  (AMF)  — H.264 + H.265"
        else:
            label = "AMD GPU  (AMF)  — H.264 only"
        gpu_options.append(label)
        gpu_label_to_key[label] = "amd"
        if best_gpu_key == "cpu":
            best_gpu_key = "amd"

    # Intel
    if "h264_qsv" in listed and _test_encoder("h264_qsv"):
        h265_works = "hevc_qsv" in listed and _test_encoder("hevc_qsv")
        if h265_works:
            hevc_ok.add("intel")
        label = "Intel GPU  (QSV)"
        gpu_options.append(label)
        gpu_label_to_key[label] = "intel"
        if best_gpu_key == "cpu":
            best_gpu_key = "intel"

    cpu_label = "CPU  (software)  — most compatible"
    hevc_ok.add("cpu")          # libx265 always works if listed
    gpu_options.append(cpu_label)
    gpu_label_to_key[cpu_label] = "cpu"

    return gpu_options, gpu_label_to_key, hevc_ok, best_gpu_key

@narrow_excepts(OSError, subprocess.SubprocessError, default=[])
def _detect_audio_devices():
    """Enumerate DShow audio input devices via ``ffmpeg -list_devices``.

    Returns an empty list on subprocess/OS failure (caught by the
    decorator).
    """
    r = subprocess.run(
        ["ffmpeg", "-list_devices", "true", "-f", "dshow", "-i", "dummy"],
        capture_output=True, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    devices, in_audio = [], False
    for line in r.stderr.splitlines():
        if "DirectShow audio devices" in line:
            in_audio = True
            continue
        if "DirectShow video devices" in line:
            in_audio = False
        if in_audio:
            m = re.search(r'"([^"]+)"', line)
            if m and "Alternative name" not in line:
                devices.append(m.group(1))
    return devices or []

def _gpu_key_from_label(label):
    l = label.lower()
    if "nvidia" in l or "nvenc" in l: return "nvidia"
    if "amd"   in l or "amf"   in l: return "amd"
    if "intel" in l or "qsv"   in l: return "intel"
    return "cpu"

def _codec_key_from_label(label):
    l = label.lower()
    if "265" in l or "hevc" in l: return "h265"
    if "av1"  in l:               return "av1"
    return "h264"

def _chroma_depth_keys(chroma_label, depth_label):
    chroma = "420"
    if "4:2:2" in chroma_label or "422" in chroma_label: chroma = "422"
    if "4:4:4" in chroma_label or "444" in chroma_label: chroma = "444"
    depth = "10" if "10" in depth_label else "8"
    return chroma, depth

def _pix_fmt(chroma_label, depth_label, gpu_key):
    chroma, depth = _chroma_depth_keys(chroma_label, depth_label)
    sw, nv, amd, qsv = PIX_FMT_MAP.get((chroma, depth), ("yuv420p",)*4)
    if gpu_key == "nvidia": return nv
    if gpu_key == "amd":    return amd
    if gpu_key == "intel":  return qsv
    return sw

def _check_compat_warning(gpu_key, codec_key, chroma_label, depth_label):
    """Return a warning string if the combination is known-unsupported, else None."""
    chroma, depth = _chroma_depth_keys(chroma_label, depth_label)
    return _UNSUPPORTED.get((gpu_key, codec_key, chroma, depth))

def _build_video_codec_args(codec_key, gpu_key, crf, speed_label, fmt):
    encoder = ENCODER_MAP[codec_key].get(gpu_key, ENCODER_MAP[codec_key]["cpu"])
    sp = SPEED_OPTIONS.get(speed_label, SPEED_OPTIONS["Ultrafast"])
    is_sw = gpu_key == "cpu"

    if is_sw:
        # libx264 / libx265 / libsvtav1
        args = ["-vcodec", encoder]
        if codec_key in ("h264", "h265"):
            args += ["-crf", str(crf), "-preset", sp[0]]
        else:  # av1 svt
            args += ["-crf", str(crf)]
    elif gpu_key == "nvidia":
        args = ["-vcodec", encoder, "-rc:v", "vbr",
                "-cq:v", str(crf), "-b:v", "0", "-maxrate:v", "100M",
                "-preset", sp[1]]
    elif gpu_key == "amd":
        qp = max(0, min(51, crf))
        args = ["-vcodec", encoder, "-quality", sp[2],
                "-qp_i", str(qp), "-qp_p", str(qp)]
    else:  # intel qsv
        args = ["-vcodec", encoder, "-global_quality", str(crf), "-preset", sp[3]]

    args += ["-pix_fmt", fmt]
    return args

# ═════════════════════════════════════════════════════════════════════════════
def run_tool():
    win = ctk.CTkToplevel()
    win.title("FFmpeg Studio")
    win.geometry("750x720")
    win.resizable(True, True)
    win.grab_set()

    # ── detect hardware once (actually tests each encoder) ───────────────────
    gpu_options, gpu_label_to_key, hevc_ok, best_gpu_key = _probe_hardware()
    audio_devices = _detect_audio_devices()

    best_gpu_label = next((g for g in gpu_options
                           if gpu_label_to_key.get(g) == best_gpu_key), gpu_options[0])

    # ── variables ────────────────────────────────────────────────────────────
    output_dir_var    = ctk.StringVar(value=str(get_path(
        "AUTOMATIONS_FFMPEG_OUTPUT_DIR", default=Path.home() / "Videos")))
    fps_var           = ctk.IntVar(value=60)
    crf_var           = ctk.IntVar(value=23)
    resolution_var    = ctk.StringVar(value="Native (your screen)")
    gpu_var           = ctk.StringVar(value=best_gpu_label)
    speed_var         = ctk.StringVar(value="Ultrafast")
    codec_var         = ctk.StringVar(value="H.264  (most compatible)")
    color_range_var   = ctk.StringVar(value="Full Range  (recommended for PC / Gaming)")
    chroma_var        = ctk.StringVar(value="4:2:0  (standard — widest compatibility)")
    bit_depth_var     = ctk.StringVar(value="8-bit")
    capture_audio_var = ctk.BooleanVar(value=True)
    audio_device_var  = ctk.StringVar(value=audio_devices[0] if audio_devices else "")

    recording_proc    = None
    record_start_time = None
    timer_running     = False
    _lockable_widgets = []

    # ── helpers ──────────────────────────────────────────────────────────────
    def set_status(msg, color="gray"):
        status_label.configure(text=msg, text_color=color)

    def browse_output():
        p = filedialog.askdirectory(title="Select Output Folder")
        if p:
            output_dir_var.set(p)

    def apply_preset(name):
        p = PRESETS[name]
        fps_var.set(p["fps"])
        crf_var.set(p["crf"])
        speed_var.set(p["speed"])
        resolution_var.set(p["resolution"])
        codec_var.set(p["codec"])
        color_range_var.set(p["color_range"])
        chroma_var.set(p["chroma"])
        bit_depth_var.set(p["bit_depth"])
        capture_audio_var.set(p["audio"])
        _refresh_crf_label()
        preset_hint_label.configure(text=p["hint"])
        set_status(f'Preset "{name}" applied.', "#4CAF50")

    def _refresh_crf_label(*_):
        v = crf_var.get()
        crf_num_label.configure(text=str(v))
        crf_desc_label.configure(text=_crf_label(v))

    crf_var.trace_add("write", _refresh_crf_label)

    def _tick_timer():
        if not timer_running:
            return
        elapsed = int(time.time() - record_start_time)
        m, s = divmod(elapsed, 60)
        h, m = divmod(m, 60)
        timer_label.configure(text=f"{h:02d}:{m:02d}:{s:02d}")
        win.after(1000, _tick_timer)

    def _resolved_gpu_key():
        """Use the probed label→key map; fall back to pattern matching."""
        return gpu_label_to_key.get(gpu_var.get(), _gpu_key_from_label(gpu_var.get()))

    def _build_cmd(out_file):
        fps        = fps_var.get()
        crf        = crf_var.get()
        gpu_key    = _resolved_gpu_key()
        codec_key  = _codec_key_from_label(codec_var.get())
        speed      = speed_var.get()
        scale      = RESOLUTIONS.get(resolution_var.get())
        full_range = "Full" in color_range_var.get()
        fmt        = _pix_fmt(chroma_var.get(), bit_depth_var.get(), gpu_key)
        audio      = capture_audio_var.get()
        adev       = audio_device_var.get()

        cmd = ["ffmpeg", "-y",
               "-f", "gdigrab",
               "-framerate", str(fps),
               "-i", "desktop"]

        has_audio = audio and adev
        if has_audio:
            cmd += ["-f", "dshow", "-i", f"audio={adev}"]

        # ── Video filter: ONE scale call handles resize + colour range ───────
        # gdigrab always captures full-range RGB (0–255). We must declare
        # in_range=full so FFmpeg uses the correct RGB→YUV conversion math.
        # Without it, FFmpeg assumes limited-range input (16–235) and the
        # conversion crushes the colours before they reach the encoder —
        # producing the washed-out look visible when comparing screen vs video.
        # out_color_matrix=bt709 ensures correct HD colour math (not BT.601).
        out_range  = "full"    if full_range else "limited"
        color_args = f"in_range=full:out_range={out_range}:out_color_matrix=bt709"

        if scale:
            vf = f"scale={scale}:{color_args}:flags=lanczos"
        else:
            vf = f"scale=iw:ih:{color_args}"

        cmd += ["-vf", vf]

        # Video codec args
        cmd += _build_video_codec_args(codec_key, gpu_key, crf, speed, fmt)

        # Colour space metadata tags — tell the container (and every player)
        # exactly what colour space these frames are in.
        cmd += [
            "-colorspace",      "bt709",
            "-color_primaries", "bt709",
            "-color_trc",       "bt709",
            "-color_range",     "pc" if full_range else "tv",
        ]

        # Audio codec
        if has_audio:
            cmd += ["-acodec", "aac", "-b:a", "192k"]

        cmd.append(out_file)
        return cmd

    def _show_ffmpeg_log(log_path, title="FFmpeg Error"):
        """Open a small window showing the FFmpeg stderr log."""
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            content = "(could not read log file)"

        # Clean up the temp log file now that we have read it
        try:
            os.remove(log_path)
        except OSError:
            pass

        log_win = ctk.CTkToplevel(win)
        log_win.title(title)
        log_win.geometry("700x400")
        log_win.grab_set()
        ctk.CTkLabel(log_win, text=title, font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#FF6B6B").pack(pady=(10, 4))
        ctk.CTkLabel(log_win, text="FFmpeg output (last 60 lines):",
                     font=ctk.CTkFont(size=10), text_color="gray").pack(anchor="w", padx=10)
        txt = ctk.CTkTextbox(log_win, width=680, height=310, font=ctk.CTkFont(family="Courier", size=10))
        txt.pack(padx=10, pady=(4, 10))
        # Show the last 60 lines — most relevant part is at the end
        lines = content.strip().splitlines()
        txt.insert("end", "\n".join(lines[-60:]))
        txt.configure(state="disabled")
        ctk.CTkButton(log_win, text="Close", command=log_win.destroy).pack(pady=(0, 10))

    def start_recording():
        nonlocal recording_proc, record_start_time, timer_running

        out_dir = output_dir_var.get().strip()
        if not out_dir:
            messagebox.showwarning("No output folder", "Please select an output folder.", parent=win)
            return

        # Warn about known-unsupported combinations before starting
        gpu_key   = _resolved_gpu_key()
        codec_key = _codec_key_from_label(codec_var.get())

        # ── Fatal conflict check: auto-fix before attempting to record ────────
        chroma, depth = _chroma_depth_keys(chroma_var.get(), bit_depth_var.get())
        fatal_msg = _FATAL_CONFLICTS.get((gpu_key, codec_key, chroma, depth))
        if fatal_msg:
            # Auto-switch bit depth to 8-bit — don't offer "try anyway"
            bit_depth_var.set("8-bit")
            messagebox.showwarning("Settings Auto-Fixed", fatal_msg, parent=win)
            return   # let user click Start again with the corrected settings

        # H.265 encoder test — catches driver-too-old errors before they create 0-byte files
        if codec_key == "h265" and gpu_key not in hevc_ok:
            enc_name = ENCODER_MAP["h265"].get(gpu_key, "hevc_nvenc")
            if not messagebox.askyesno(
                "H.265 Not Supported",
                f"The H.265 encoder ({enc_name}) did not pass the hardware test on startup.\n\n"
                f"This is likely because your GPU driver is too old.\n"
                f"For NVIDIA: driver 570.0+ is required.\n\n"
                f"Switch to H.264 for a guaranteed working recording, "
                f"or click Yes to try H.265 anyway.",
                parent=win,
            ):
                codec_var.set("H.264  (most compatible)")
                return

        warn = _check_compat_warning(gpu_key, codec_key, chroma_var.get(), bit_depth_var.get())
        if warn:
            if not messagebox.askyesno("Compatibility Warning",
                                       f"{warn}\n\nContinue anyway?", parent=win):
                return

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        out_file  = os.path.join(out_dir, f"gameplay_{timestamp}.mp4")
        cmd       = _build_cmd(out_file)

        # Log stderr to a temp file so we can read it if FFmpeg fails
        log_fd, log_path = tempfile.mkstemp(suffix="_ffmpeg.log", prefix="ffstudio_")
        os.close(log_fd)

        log_file = None
        try:
            log_file = open(log_path, "w", encoding="utf-8")
            recording_proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=log_file,
                stderr=log_file,         # both streams → log file
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        except FileNotFoundError:
            messagebox.showerror("FFmpeg not found",
                                 "FFmpeg was not found. Make sure it is installed and in your PATH.", parent=win)
            return
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            messagebox.showerror("Error", str(e), parent=win)
            return
        finally:
            # If Popen failed, close the log file handle immediately
            if log_file and recording_proc is None:
                try:
                    log_file.close()
                except OSError:
                    pass

        # Disable controls immediately while we verify startup
        start_rec_btn.configure(state="disabled", text="Starting…")
        _set_lock("disabled")
        set_status("Starting FFmpeg…", "#FFA500")

        def _verify_startup():
            """Wait 2.5 s then check if FFmpeg is still alive."""
            time.sleep(2.5)
            ret = recording_proc.poll()

            if ret is not None:
                # FFmpeg already exited → failure
                try:
                    log_file.flush()
                    log_file.close()
                except OSError:
                    pass
                # Remove 0-byte output file if it exists
                try:
                    if os.path.exists(out_file) and os.path.getsize(out_file) == 0:
                        os.remove(out_file)
                except OSError:
                    pass

                def _on_fail():
                    start_rec_btn.configure(state="normal", text="▶  Start Recording")
                    stop_rec_btn.configure(state="disabled")
                    _set_lock("normal")
                    set_status("Recording failed — see error log.", "red")
                    _show_ffmpeg_log(log_path, "Recording Failed")

                win.after(0, _on_fail)
            else:
                # Still running → recording started successfully
                nonlocal record_start_time, timer_running
                record_start_time = time.time()
                timer_running = True
                win.after(0, _tick_timer)

                def _on_success():
                    start_rec_btn.configure(text="▶  Start Recording")
                    stop_rec_btn.configure(state="normal")
                    set_status(f"Recording  →  {os.path.basename(out_file)}", "#4CAF50")
                    out_file_label.configure(text=out_file)

                win.after(0, _on_success)

                # Store log_file ref so stop_recording can close and clean up
                recording_proc._log_file = log_file
                recording_proc._log_path = log_path

        threading.Thread(target=_verify_startup, daemon=True).start()

    def stop_recording():
        nonlocal recording_proc, timer_running
        if recording_proc is None:
            return
        timer_running = False
        set_status("Stopping — finalising file…", "#FFA500")
        try:
            recording_proc.stdin.write(b"q")
            recording_proc.stdin.flush()
            recording_proc.wait(timeout=15)
        except (OSError, BrokenPipeError, subprocess.TimeoutExpired):
            recording_proc.kill()
        # Close the log file handle and clean up temp log
        lf = getattr(recording_proc, "_log_file", None)
        if lf:
            try:
                lf.close()
            except OSError:
                pass
        lp = getattr(recording_proc, "_log_path", None)
        if lp:
            try:
                os.remove(lp)
            except OSError:
                pass
        recording_proc = None
        start_rec_btn.configure(state="normal")
        stop_rec_btn.configure(state="disabled")
        _set_lock("normal")
        set_status("Recording saved.", "#4CAF50")

    def _set_lock(state):
        for w in _lockable_widgets:
            try:
                w.configure(state=state)
            except tk.TclError:
                pass

    # ════════════════════════════════════════════════════════════════════════
    # UI Layout
    # ════════════════════════════════════════════════════════════════════════
    ctk.CTkLabel(win, text="FFmpeg Studio",
                 font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(14, 0))
    ctk.CTkLabel(win, text="Record gameplay  •  Convert videos",
                 font=ctk.CTkFont(size=12), text_color="gray").pack(pady=(2, 6))

    tabview = ctk.CTkTabview(win, width=720, height=600)
    tabview.pack(padx=14, pady=(0, 4), fill="both", expand=True)
    tabview.add("Record")
    tabview.add("Capture")
    tabview.add("Convert")

    # ══════════════════════════════════════════════════════════════════════════
    # RECORD TAB
    # ══════════════════════════════════════════════════════════════════════════
    rt_scroll = ctk.CTkScrollableFrame(tabview.tab("Record"), fg_color="transparent")
    rt_scroll.pack(fill="both", expand=True)
    rt = rt_scroll

    def _section(parent, text):
        f = ctk.CTkFrame(parent, fg_color="#1e1e1e", corner_radius=10)
        f.pack(fill="x", padx=6, pady=(8, 0))
        ctk.CTkLabel(f, text=text, font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#3a9fd8").pack(anchor="w", padx=12, pady=(8, 4))
        return f

    def _row(parent):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", padx=12, pady=(0, 2))
        return f

    def _hint(parent, text):
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=10),
                     text_color="#666666", wraplength=640, justify="left").pack(
                         anchor="w", padx=16, pady=(0, 6))

    def _label(parent, text, width=145):
        ctk.CTkLabel(parent, text=text, width=width, anchor="w").pack(side="left")

    # ── Presets ──────────────────────────────────────────────────────────────
    ps = _section(rt, "Quick Presets")
    btn_row = _row(ps)
    preset_colors = {
        "Max Quality":     ("#1a6b3a", "#145530"),
        "Balanced":        ("#1a4f8c", "#133b6e"),
        "Streaming Ready": ("#7a4a00", "#5c3800"),
        "Storage Saver":   ("#4a1a7a", "#38135c"),
    }
    for name, (fg, hov) in preset_colors.items():
        ctk.CTkButton(btn_row, text=name, width=148, height=34,
                      fg_color=fg, hover_color=hov,
                      command=lambda n=name: apply_preset(n)).pack(side="left", padx=3, pady=6)

    preset_hint_label = ctk.CTkLabel(ps, text="Select a preset above, or customize the options below.",
                                     font=ctk.CTkFont(size=10), text_color="#888888",
                                     wraplength=660, justify="left")
    preset_hint_label.pack(anchor="w", padx=14, pady=(0, 8))

    # ── Output Folder ─────────────────────────────────────────────────────────
    ofs = _section(rt, "Output Folder")
    r = _row(ofs)
    out_entry = ctk.CTkEntry(r, textvariable=output_dir_var, width=490)
    out_entry.pack(side="left")
    browse_btn = ctk.CTkButton(r, text="Browse", width=90, command=browse_output)
    browse_btn.pack(side="left", padx=(8, 0))
    _lockable_widgets += [out_entry, browse_btn]

    # ── Video Settings ────────────────────────────────────────────────────────
    vs = _section(rt, "Video Settings")

    r = _row(vs)
    _label(r, "Resolution:")
    res_menu = ctk.CTkOptionMenu(r, variable=resolution_var,
                                 values=list(RESOLUTIONS.keys()), width=260)
    res_menu.pack(side="left")
    _lockable_widgets.append(res_menu)
    _hint(vs, "Native captures your full screen at its actual resolution — best for gameplay. "
              "Lower options reduce file size and encoding load.")

    r = _row(vs)
    _label(r, "Framerate (FPS):")
    for val, lbl in {30: "30 fps  (smooth)", 60: "60 fps  (best for action)", 120: "120 fps  (ultra)"}.items():
        rb = ctk.CTkRadioButton(r, text=lbl, variable=fps_var, value=val)
        rb.pack(side="left", padx=(0, 12))
        _lockable_widgets.append(rb)
    _hint(vs, "60 fps is the sweet spot for most gameplay. 120 fps produces very large files.")

    r = _row(vs)
    _label(r, "GPU / Encoder:")
    gpu_menu = ctk.CTkOptionMenu(r, variable=gpu_var, values=gpu_options, width=320)
    gpu_menu.pack(side="left")
    _lockable_widgets.append(gpu_menu)
    _hint(vs, "GPU encoders (NVIDIA/AMD) offload encoding to your graphics card — minimal CPU impact while gaming.\n"
              "CPU gives the highest quality per file size, but uses more processor during recording.")

    r = _row(vs)
    _label(r, "Quality (CRF):")
    q_slider = ctk.CTkSlider(r, from_=0, to=51, variable=crf_var, width=270, number_of_steps=51)
    q_slider.pack(side="left")
    crf_num_label = ctk.CTkLabel(r, text="23", width=28, font=ctk.CTkFont(weight="bold"))
    crf_num_label.pack(side="left", padx=(8, 4))
    crf_desc_label = ctk.CTkLabel(r, text=_crf_label(23), text_color="#4CAF50",
                                  font=ctk.CTkFont(size=11))
    crf_desc_label.pack(side="left")
    _lockable_widgets.append(q_slider)
    _hint(vs, "Lower = better quality and larger files. 16–23 is ideal for footage you plan to edit later.")

    r = _row(vs)
    _label(r, "Encoding Speed:")
    for val, lbl in {"Ultrafast": "Ultrafast  (lowest CPU — use while gaming)",
                     "Fast":      "Fast  (slightly better compression)",
                     "Medium":    "Medium  (best compression — archiving only)"}.items():
        rb = ctk.CTkRadioButton(r, text=lbl, variable=speed_var, value=val)
        rb.pack(side="left", padx=(0, 8))
        _lockable_widgets.append(rb)
    _hint(vs, "Ultrafast strongly recommended while playing — it minimises CPU impact on your game.")

    # ── Color & Codec ─────────────────────────────────────────────────────────
    cs = _section(rt, "Color & Codec")

    CODEC_OPTIONS = [
        "H.264  (most compatible)",
        "H.265 / HEVC  (better quality, smaller files)",
        "AV1  (best quality, very slow — archiving only)",
    ]
    r = _row(cs)
    _label(r, "Video Codec:")
    codec_menu = ctk.CTkOptionMenu(r, variable=codec_var, values=CODEC_OPTIONS, width=340)
    codec_menu.pack(side="left")
    _lockable_widgets.append(codec_menu)
    _hint(cs, "H.265 gives noticeably better color and detail than H.264 at the same file size, with only a small CPU/GPU increase.\n"
              "AV1 is the best codec available but encodes slowly — only use it for archiving, not live recording.")

    COLOR_RANGE_OPTIONS = [
        "Full Range  (recommended for PC / Gaming)",
        "Limited Range  (broadcast / YouTube standard)",
    ]
    r = _row(cs)
    _label(r, "Color Range:")
    cr_menu = ctk.CTkOptionMenu(r, variable=color_range_var, values=COLOR_RANGE_OPTIONS, width=340)
    cr_menu.pack(side="left")
    _lockable_widgets.append(cr_menu)
    _hint(cs, "This is the most common cause of washed-out or crushed colors in recordings.\n"
              "Full Range preserves all 0–255 color values from your PC display (correct for gaming).\n"
              "Limited Range uses 16–235 (broadcast standard) — use this if uploading to YouTube/streaming.")

    CHROMA_OPTIONS = [
        "4:2:0  (standard — widest compatibility)",
        "4:2:2  (better color — good for editing)",
        "4:4:4  (full color — best for editing)",
    ]
    r = _row(cs)
    _label(r, "Chroma Subsampling:")
    chroma_menu = ctk.CTkOptionMenu(r, variable=chroma_var, values=CHROMA_OPTIONS, width=340)
    chroma_menu.pack(side="left")
    _lockable_widgets.append(chroma_menu)
    _hint(cs, "Controls how much color information is stored vs. just brightness.\n"
              "4:2:0 — standard for video; color detail is halved (fine for most recordings).\n"
              "4:2:2 — doubles the color resolution; better if you plan to color-grade the footage.\n"
              "4:4:4 — full color per pixel; best quality for editing, largest files, may not play on all devices.")

    DEPTH_OPTIONS = ["8-bit", "10-bit  (smoother gradients, less banding)"]
    r = _row(cs)
    _label(r, "Bit Depth:")
    depth_menu = ctk.CTkOptionMenu(r, variable=bit_depth_var, values=DEPTH_OPTIONS, width=340)
    depth_menu.pack(side="left")
    _lockable_widgets.append(depth_menu)
    _hint(cs, "8-bit — standard; works with all encoders and players.\n"
              "10-bit — 4× more color levels, eliminates banding in dark areas and smooth gradients.\n"
              "⚠ GPU H.264 encoders (NVENC, AMF, QSV) do NOT support 10-bit — it will be auto-switched to 8-bit.\n"
              "For 10-bit GPU recording, use H.265 instead. CPU encoder supports 10-bit with any codec.")

    # ── Audio ─────────────────────────────────────────────────────────────────
    aus = _section(rt, "Audio")
    r = _row(aus)
    aud_chk = ctk.CTkCheckBox(r, text="Capture audio", variable=capture_audio_var)
    aud_chk.pack(side="left")
    _lockable_widgets.append(aud_chk)

    r = _row(aus)
    _label(r, "Audio Device:")
    if audio_devices:
        aud_menu = ctk.CTkOptionMenu(r, variable=audio_device_var,
                                     values=audio_devices, width=380)
        aud_menu.pack(side="left")
        _lockable_widgets.append(aud_menu)
        _hint(aus, "Select your microphone or headset.\n"
                   "For in-game / desktop audio (what you hear): enable 'Stereo Mix' in Windows Sound Settings "
                   "→ Recording devices → right-click → Show Disabled Devices.")
    else:
        ctk.CTkLabel(r, text="No audio devices found.", text_color="#FF6B6B").pack(side="left")

    # ── Record Controls ───────────────────────────────────────────────────────
    ctrl = ctk.CTkFrame(rt, fg_color="#1e1e1e", corner_radius=10)
    ctrl.pack(fill="x", padx=6, pady=(12, 8))

    timer_row = ctk.CTkFrame(ctrl, fg_color="transparent")
    timer_row.pack(pady=(10, 4))
    ctk.CTkLabel(timer_row, text="● REC",
                 font=ctk.CTkFont(size=11, weight="bold"), text_color="#FF4444").pack(side="left", padx=(0, 10))
    timer_label = ctk.CTkLabel(timer_row, text="00:00:00",
                               font=ctk.CTkFont(size=26, weight="bold"))
    timer_label.pack(side="left")

    rec_btn_row = ctk.CTkFrame(ctrl, fg_color="transparent")
    rec_btn_row.pack(pady=(4, 6))
    start_rec_btn = ctk.CTkButton(
        rec_btn_row, text="▶  Start Recording", width=200, height=44,
        font=ctk.CTkFont(size=14, weight="bold"),
        fg_color="#2e7d32", hover_color="#1b5e20",
        command=start_recording,
    )
    start_rec_btn.pack(side="left", padx=10)
    stop_rec_btn = ctk.CTkButton(
        rec_btn_row, text="■  Stop Recording", width=200, height=44,
        font=ctk.CTkFont(size=14, weight="bold"),
        fg_color="#b71c1c", hover_color="#7f0000",
        command=stop_recording, state="disabled",
    )
    stop_rec_btn.pack(side="left", padx=10)

    out_file_label = ctk.CTkLabel(ctrl, text="", font=ctk.CTkFont(size=10),
                                  text_color="gray", wraplength=680)
    out_file_label.pack(pady=(0, 8))

    # ══════════════════════════════════════════════════════════════════════════
    # CAPTURE TAB
    # ══════════════════════════════════════════════════════════════════════════
    cap_tab = tabview.tab("Capture")
    cap_scroll = ctk.CTkScrollableFrame(cap_tab, fg_color="transparent")
    cap_scroll.pack(fill="both", expand=True)
    cp = cap_scroll

    cap_out_var     = ctk.StringVar(value=str(get_path(
        "AUTOMATIONS_FFMPEG_CAPTURE_DIR", default=Path.home() / "Pictures")))
    cap_fmt_var     = ctk.StringVar(value="PNG  (lossless — best quality)")
    cap_quality_var = ctk.IntVar(value=90)
    cap_delay_var   = ctk.IntVar(value=0)
    cap_res_var     = ctk.StringVar(value="Native (your screen)")
    cap_range_var   = ctk.StringVar(value="Full Range  (recommended for PC / Gaming)")
    cap_mode_var    = ctk.StringVar(value="Full Screen")

    # mutable region — updated by selector and manual fields
    cap_region = {"x": 0, "y": 0, "w": 1920, "h": 1080}

    CAP_FORMATS = {
        "PNG  (lossless — best quality)":            ("png",  None),
        "JPEG  (smaller file, slight quality loss)": ("jpg",  "jpeg_quality"),
        "WebP  (modern — small + great quality)":    ("webp", "webp_quality"),
    }

    # ── Output Folder ────────────────────────────────────────────────────────
    cap_ofs = _section(cp, "Output Folder")
    r = _row(cap_ofs)
    ctk.CTkEntry(r, textvariable=cap_out_var, width=490).pack(side="left")
    ctk.CTkButton(r, text="Browse", width=90,
                  command=lambda: cap_out_var.set(
                      filedialog.askdirectory(title="Select Output Folder") or cap_out_var.get()
                  )).pack(side="left", padx=(8, 0))

    # ── Capture Region ────────────────────────────────────────────────────────
    crs = _section(cp, "Capture Region")

    mode_row = _row(crs)
    ctk.CTkRadioButton(mode_row, text="Full Screen",
                       variable=cap_mode_var, value="Full Screen").pack(side="left", padx=(0, 24))
    ctk.CTkRadioButton(mode_row, text="Custom Region  (crop a specific area)",
                       variable=cap_mode_var, value="Custom Region").pack(side="left")
    _hint(crs, "Custom Region lets you define exactly which area of the screen to capture — "
               "no need for delay, even with this app visible.")

    # region controls frame — shown only in Custom Region mode
    region_frame = ctk.CTkFrame(crs, fg_color="#161616", corner_radius=8)

    def _toggle_region_frame(*_):
        if cap_mode_var.get() == "Custom Region":
            region_frame.pack(fill="x", padx=10, pady=(2, 8))
        else:
            region_frame.pack_forget()

    cap_mode_var.trace_add("write", _toggle_region_frame)

    # ── Region display + selector button ─────────────────────────────────────
    region_info_label = ctk.CTkLabel(
        region_frame, text="No region selected — click 'Select on Screen' or use a preset",
        font=ctk.CTkFont(size=11), text_color="#FFA500")
    region_info_label.pack(anchor="w", padx=12, pady=(8, 4))

    def _update_region_display():
        x, y, w, h = cap_region["x"], cap_region["y"], cap_region["w"], cap_region["h"]
        ratio = _guess_ratio(w, h)
        region_info_label.configure(
            text=f"Region: {w}×{h}  ({ratio})  at position ({x}, {y})",
            text_color="#4CAF50")
        cap_rx_var.set(str(x)); cap_ry_var.set(str(y))
        cap_rw_var.set(str(w)); cap_rh_var.set(str(h))

    sel_row = _row(region_frame)
    sel_btn = ctk.CTkButton(
        sel_row, text="⊹  Select on Screen", width=180, height=34,
        fg_color="#3a7ebf", hover_color="#2b6194",
        command=lambda: _open_region_selector())
    sel_btn.pack(side="left", padx=(0, 12))
    ctk.CTkLabel(sel_row, text="Hold Shift while dragging to snap to 16:9",
                 font=ctk.CTkFont(size=10), text_color="#555555").pack(side="left")

    # ── Preset dimensions ─────────────────────────────────────────────────────
    ctk.CTkLabel(region_frame, text="Presets (centered on screen):",
                 font=ctk.CTkFont(size=11, weight="bold"),
                 text_color="#888888").pack(anchor="w", padx=12, pady=(8, 2))

    preset_grid = ctk.CTkFrame(region_frame, fg_color="transparent")
    preset_grid.pack(fill="x", padx=10, pady=(0, 6))

    def _apply_region_preset(w, h):
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()
        x  = max(0, (sw - w) // 2)
        y  = max(0, (sh - h) // 2)
        cap_region.update({"x": x, "y": y, "w": min(w, sw), "h": min(h, sh)})
        _update_region_display()

    for i, (label, pw, ph, desc) in enumerate(CROP_PRESETS):
        col = i % 4
        row_n = i // 4
        btn = ctk.CTkButton(
            preset_grid, text=f"{label}\n{desc}",
            width=155, height=40, font=ctk.CTkFont(size=10),
            fg_color="#2a2a2a", hover_color="#3a3a3a",
            command=lambda w=pw, h=ph: _apply_region_preset(w, h))
        btn.grid(row=row_n, column=col, padx=3, pady=3)

    # ── Manual X/Y/W/H fields ─────────────────────────────────────────────────
    ctk.CTkLabel(region_frame, text="Manual entry:",
                 font=ctk.CTkFont(size=11, weight="bold"),
                 text_color="#888888").pack(anchor="w", padx=12, pady=(6, 2))

    manual_row = _row(region_frame)
    cap_rx_var = ctk.StringVar(value="0")
    cap_ry_var = ctk.StringVar(value="0")
    cap_rw_var = ctk.StringVar(value="1920")
    cap_rh_var = ctk.StringVar(value="1080")

    for lbl, var in [("X:", cap_rx_var), ("Y:", cap_ry_var),
                     ("W:", cap_rw_var), ("H:", cap_rh_var)]:
        ctk.CTkLabel(manual_row, text=lbl, width=20, anchor="e").pack(side="left")
        ctk.CTkEntry(manual_row, textvariable=var, width=68).pack(side="left", padx=(2, 8))

    def _apply_manual_region():
        try:
            x, y = int(cap_rx_var.get()), int(cap_ry_var.get())
            w, h = int(cap_rw_var.get()), int(cap_rh_var.get())
            if w < 2 or h < 2:
                raise ValueError
            cap_region.update({"x": x, "y": y, "w": w, "h": h})
            _update_region_display()
        except ValueError:
            set_status("Invalid region values.", "red")

    ctk.CTkButton(manual_row, text="Apply", width=70,
                  command=_apply_manual_region).pack(side="left")

    ctk.CTkLabel(region_frame, text="",
                 height=4).pack()  # spacer

    # ── Region overlay selector ───────────────────────────────────────────────
    def _open_region_selector():
        win.iconify()
        win.after(300, _capture_screen_then_overlay)   # wait for window to fully minimise

    def _capture_screen_then_overlay():
        sw = win.winfo_screenwidth()
        sh = win.winfo_screenheight()

        # Screenshot taken while the app is minimised so it is not in frame
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="ffstudio_sel_", suffix=".png")
        os.close(tmp_fd)
        subprocess.run(
            ["ffmpeg", "-y", "-f", "gdigrab",
             "-video_size", f"{sw}x{sh}",
             "-i", "desktop", "-vframes", "1", tmp_path],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        _show_visual_overlay(sw, sh, tmp_path)

    def _show_visual_overlay(sw, sh, bg_path):
        ov = tk.Toplevel()
        ov.geometry(f"{sw}x{sh}+0+0")
        ov.overrideredirect(True)
        ov.attributes("-topmost", True)
        ov.lift()
        ov.focus_force()

        cv = tk.Canvas(ov, width=sw, height=sh, bg="black",
                       highlightthickness=0, cursor="crosshair")
        cv.pack()

        # ── Background: actual screenshot ─────────────────────────────────
        bg_img = None
        try:
            bg_img = tk.PhotoImage(file=bg_path)
            cv.create_image(0, 0, anchor="nw", image=bg_img, tags="bg")
            cv._bg_ref = bg_img          # prevent garbage-collection
        except (OSError, tk.TclError):
            pass                         # fallback: plain black canvas

        # ── Initial full-screen dim (stipple = 50 % grey dots over screenshot) ──
        DIM   = "#000000"
        STIP  = "gray50"
        cv.create_rectangle(0, 0, sw, sh, fill=DIM, stipple=STIP,
                            outline="", tags="dim_initial")

        # ── Instruction bar (semi-opaque dark pill at top) ────────────────
        bar_h = 48
        cv.create_rectangle(0, 0, sw, bar_h, fill="#000000",
                            stipple="gray75", outline="", tags="bar_bg")
        cv.create_text(sw // 2, bar_h // 2,
                       text="Click and drag to select a region   •   "
                            "Shift = snap to 16:9   •   Esc = cancel",
                       fill="white", font=("Arial", 13, "bold"), tags="bar_txt")

        # ── Live selection elements ────────────────────────────────────────
        # 4 dim rectangles that surround the selection (replace full-screen dim)
        for tag in ("dim_t", "dim_b", "dim_l", "dim_r"):
            cv.create_rectangle(0, 0, 0, 0, fill=DIM, stipple=STIP,
                                outline="", tags=tag)

        # Selection border + corner handles
        sel_border = cv.create_rectangle(0, 0, 0, 0,
                                         outline="#00ff88", width=2,
                                         fill="", tags="sel")
        # Corner handles (small squares)
        handle_size = 6
        handles = []
        for _ in range(4):
            h = cv.create_rectangle(0, 0, handle_size, handle_size,
                                    fill="#00ff88", outline="white",
                                    width=1, tags="sel_handle")
            handles.append(h)

        # Dimension badge (dark pill behind text)
        dim_badge_bg  = cv.create_rectangle(0, 0, 0, 0,
                                            fill="#000000", stipple="gray75",
                                            outline="", tags="dim_badge")
        dim_badge_txt = cv.create_text(0, 0, text="",
                                       fill="white",
                                       font=("Arial", 13, "bold"),
                                       tags="dim_badge_txt")

        # Position label (top-left of selection)
        pos_txt = cv.create_text(0, 0, text="", anchor="nw",
                                 fill="#cccccc", font=("Arial", 10),
                                 tags="pos_txt")

        def _hide_initial_dim():
            cv.itemconfig("dim_initial", state="hidden")

        state = {"sx": 0, "sy": 0, "active": False}

        def _apply_snap(sx, sy, ex, ey, shift_held):
            if shift_held:
                rw, rh = abs(ex - sx), abs(ey - sy)
                if rw / max(rh, 1) > 16 / 9:
                    rh = int(rw * 9 / 16)
                else:
                    rw = int(rh * 16 / 9)
                ex = sx + (rw  if ex >= sx else -rw)
                ey = sy + (rh  if ey >= sy else -rh)
            return ex, ey

        def _redraw(sx, sy, ex, ey):
            rx,  ry  = min(sx, ex), min(sy, ey)
            rx2, ry2 = max(sx, ex), max(sy, ey)
            rw,  rh  = rx2 - rx,   ry2 - ry

            # ── 4 surrounding dim panels ──────────────────────────────────
            cv.coords("dim_t", 0,   0,   sw,  ry)          # above
            cv.coords("dim_b", 0,   ry2, sw,  sh)          # below
            cv.coords("dim_l", 0,   ry,  rx,  ry2)         # left
            cv.coords("dim_r", rx2, ry,  sw,  ry2)         # right

            # ── Selection border ──────────────────────────────────────────
            cv.coords(sel_border, rx, ry, rx2, ry2)

            # ── Corner handles ────────────────────────────────────────────
            corners = [(rx, ry), (rx2, ry), (rx, ry2), (rx2, ry2)]
            hs = handle_size
            for hid, (cx, cy) in zip(handles, corners):
                cv.coords(hid, cx - hs, cy - hs, cx + hs, cy + hs)

            # ── Dimension badge ───────────────────────────────────────────
            ratio   = _guess_ratio(rw, rh)
            dim_str = f"  {rw} × {rh}   {ratio}  "
            mid_x   = rx + rw // 2
            mid_y   = ry + rh // 2
            cv.coords(dim_badge_txt, mid_x, mid_y)
            cv.itemconfig(dim_badge_txt, text=dim_str)
            bbox = cv.bbox(dim_badge_txt)
            if bbox:
                pad = 4
                cv.coords(dim_badge_bg,
                          bbox[0] - pad, bbox[1] - pad,
                          bbox[2] + pad, bbox[3] + pad)

            # ── Position label ────────────────────────────────────────────
            ty = max(ry - 22, bar_h + 4)
            cv.coords(pos_txt, rx + 2, ty)
            cv.itemconfig(pos_txt, text=f"({rx}, {ry})")

            # Raise interactive elements above dim panels
            for tag in ("sel", "sel_handle", "dim_badge", "dim_badge_txt", "pos_txt"):
                cv.tag_raise(tag)

        def on_press(e):
            state["sx"] = e.x
            state["sy"] = e.y
            state["active"] = True
            _hide_initial_dim()

        def on_drag(e):
            if not state["active"]:
                return
            ex, ey = _apply_snap(state["sx"], state["sy"], e.x, e.y, bool(e.state & 0x1))
            _redraw(state["sx"], state["sy"], ex, ey)

        def on_release(e):
            if not state["active"]:
                return
            ex, ey = _apply_snap(state["sx"], state["sy"], e.x, e.y, bool(e.state & 0x1))
            try:
                ov.destroy()
            except tk.TclError:
                pass
            win.deiconify()
            win.lift()
            x, y = min(state["sx"], ex), min(state["sy"], ey)
            w, h = abs(ex - state["sx"]), abs(ey - state["sy"])
            if w > 4 and h > 4:
                cap_region.update({"x": x, "y": y, "w": w, "h": h})
                win.after(100, _update_region_display)
            try:
                os.remove(bg_path)
            except OSError:
                pass

        def on_escape(e):
            try:
                ov.destroy()
            except tk.TclError:
                pass
            win.deiconify()
            try:
                os.remove(bg_path)
            except OSError:
                pass

        cv.bind("<ButtonPress-1>",   on_press)
        cv.bind("<B1-Motion>",       on_drag)
        cv.bind("<ButtonRelease-1>", on_release)
        ov.bind("<Escape>",          on_escape)
        ov.grab_set()

    # ── Capture Settings ─────────────────────────────────────────────────────
    cap_vs = _section(cp, "Image Settings")

    r = _row(cap_vs)
    _label(r, "Scale output to:")
    ctk.CTkOptionMenu(r, variable=cap_res_var,
                      values=list(RESOLUTIONS.keys()), width=260).pack(side="left")
    _hint(cap_vs, "Native keeps the captured area at its actual size. Scale-down options reduce file size.\n"
                  "Useful for sharing: capture a 4K region and scale down to 1080p for the image file.")

    r = _row(cap_vs)
    _label(r, "Color Range:")
    ctk.CTkOptionMenu(r, variable=cap_range_var,
                      values=["Full Range  (recommended for PC / Gaming)",
                              "Limited Range  (broadcast standard)"],
                      width=320).pack(side="left")
    _hint(cap_vs, "Full Range preserves exact screen colours (0–255). Matches what you see on screen.")

    r = _row(cap_vs)
    _label(r, "Format:")
    ctk.CTkOptionMenu(r, variable=cap_fmt_var,
                      values=list(CAP_FORMATS.keys()), width=360).pack(side="left")
    _hint(cap_vs, "PNG — lossless, largest files. Perfect for editing or archiving game screenshots.\n"
                  "JPEG — compressed, smaller. Good for sharing on Discord, Twitter, etc.\n"
                  "WebP — modern: smaller than JPEG at same quality. Best for web and social media.")

    r = _row(cap_vs)
    _label(r, "Quality (JPEG/WebP):")
    cap_q_slider = ctk.CTkSlider(r, from_=1, to=100, variable=cap_quality_var, width=220, number_of_steps=99)
    cap_q_slider.pack(side="left")
    cap_q_label = ctk.CTkLabel(r, text="90", width=30, font=ctk.CTkFont(weight="bold"))
    cap_q_label.pack(side="left", padx=(8, 0))
    cap_quality_var.trace_add("write", lambda *_: cap_q_label.configure(text=str(cap_quality_var.get())))
    _hint(cap_vs, "85–95 is the sweet spot — visually indistinguishable from lossless. PNG ignores this.")

    # ── Delay ────────────────────────────────────────────────────────────────
    cap_ds = _section(cp, "Capture Delay")
    r = _row(cap_ds)
    _label(r, "Delay before capture:")
    for val, lbl in {0: "None", 3: "3 sec", 5: "5 sec", 10: "10 sec"}.items():
        ctk.CTkRadioButton(r, text=lbl, variable=cap_delay_var, value=val).pack(side="left", padx=(0, 14))
    _hint(cap_ds, "With Custom Region selected, delay is usually not needed — the region is already defined.\n"
                  "Use delay for Full Screen if you need to switch windows first.")

    # ── Capture Controls ─────────────────────────────────────────────────────
    cap_ctrl = ctk.CTkFrame(cp, fg_color="#1e1e1e", corner_radius=10)
    cap_ctrl.pack(fill="x", padx=6, pady=(12, 8))

    cap_countdown_label = ctk.CTkLabel(cap_ctrl, text="",
                                       font=ctk.CTkFont(size=28, weight="bold"), text_color="#FFA500")
    cap_countdown_label.pack(pady=(10, 2))

    cap_btn_row = ctk.CTkFrame(cap_ctrl, fg_color="transparent")
    cap_btn_row.pack(pady=(4, 6))

    def _do_capture():
        out_d   = cap_out_var.get().strip()
        fmt_key = cap_fmt_var.get()
        ext, _  = CAP_FORMATS[fmt_key]
        scale   = RESOLUTIONS.get(cap_res_var.get())
        quality = cap_quality_var.get()
        full_r  = "Full" in cap_range_var.get()
        use_region = cap_mode_var.get() == "Custom Region"

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        out_file  = os.path.join(out_d, f"capture_{timestamp}.{ext}")

        out_range  = "full" if full_r else "limited"
        color_args = f"in_range=full:out_range={out_range}:out_color_matrix=bt709"

        if scale:
            vf = f"scale={scale}:{color_args}:flags=lanczos"
        else:
            vf = f"scale=iw:ih:{color_args}"

        cmd = ["ffmpeg", "-y", "-f", "gdigrab"]

        if use_region:
            rx = cap_region["x"]; ry = cap_region["y"]
            rw = cap_region["w"]; rh = cap_region["h"]
            # gdigrab requires even dimensions
            rw += rw % 2; rh += rh % 2
            cmd += ["-offset_x", str(rx), "-offset_y", str(ry),
                    "-video_size", f"{rw}x{rh}"]

        cmd += ["-i", "desktop", "-vframes", "1", "-vf", vf]

        if ext == "jpg":
            q = max(1, min(31, round((100 - quality) * 30 / 99) + 1))
            cmd += ["-q:v", str(q)]
        elif ext == "webp":
            cmd += ["-quality", str(quality)]

        cmd += [
            "-colorspace", "bt709", "-color_primaries", "bt709",
            "-color_trc",  "bt709", "-color_range", "pc" if full_r else "tv",
            out_file,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode == 0:
                win.after(0, lambda: (
                    cap_result_label.configure(text=out_file),
                    set_status(f"Screenshot saved  →  {os.path.basename(out_file)}", "#4CAF50"),
                    cap_btn.configure(state="normal", text="📷  Capture Screenshot"),
                ))
            else:
                err = result.stderr.decode("utf-8", errors="replace")[-200:]
                win.after(0, lambda e=err: (
                    set_status("Capture failed.", "red"),
                    cap_result_label.configure(text=e, text_color="#FF6B6B"),
                    cap_btn.configure(state="normal", text="📷  Capture Screenshot"),
                ))
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            win.after(0, lambda: (
                set_status(f"Error: {e}", "red"),
                cap_btn.configure(state="normal", text="📷  Capture Screenshot"),
            ))

    def _start_capture_with_delay():
        delay = cap_delay_var.get()
        cap_btn.configure(state="disabled")
        cap_result_label.configure(text="", text_color="gray")

        if delay == 0:
            cap_countdown_label.configure(text="")
            set_status("Capturing…", "#FFA500")
            threading.Thread(target=_do_capture, daemon=True).start()
            return

        def _countdown(remaining):
            if remaining > 0:
                cap_countdown_label.configure(text=f"Capturing in {remaining}…")
                win.after(1000, lambda: _countdown(remaining - 1))
            else:
                cap_countdown_label.configure(text="📷")
                set_status("Capturing…", "#FFA500")
                threading.Thread(target=_do_capture, daemon=True).start()
                win.after(500, lambda: cap_countdown_label.configure(text=""))

        _countdown(delay)

    cap_btn = ctk.CTkButton(
        cap_btn_row, text="📷  Capture Screenshot", width=220, height=44,
        font=ctk.CTkFont(size=14, weight="bold"),
        fg_color="#1a4f8c", hover_color="#133b6e",
        command=_start_capture_with_delay,
    )
    cap_btn.pack()

    cap_result_label = ctk.CTkLabel(cap_ctrl, text="", font=ctk.CTkFont(size=10),
                                    text_color="gray", wraplength=680)
    cap_result_label.pack(pady=(2, 8))

    # ══════════════════════════════════════════════════════════════════════════
    # CONVERT TAB  —  Web-friendly output with platform presets
    # ══════════════════════════════════════════════════════════════════════════
    conv_tab = tabview.tab("Convert")
    conv_scroll = ctk.CTkScrollableFrame(conv_tab, fg_color="transparent")
    conv_scroll.pack(fill="both", expand=True)
    ct = conv_scroll

    # ── Convert presets (platform targets) ───────────────────────────────────
    CONV_PRESETS = {
        "YouTube": {
            "res": "1080p (1920×1080)", "fmt": "mp4",  "codec": "libx264", "crf": 18,
            "audio": "192k", "limited": True, "faststart": True,
            "hint": "H.264 1080p, high quality. Limited Range for correct YouTube colors.\n"
                    "✓ faststart enabled — playback starts before full upload.",
        },
        "YouTube 4K": {
            "res": "4K (3840×2160)", "fmt": "mp4", "codec": "libx265", "crf": 20,
            "audio": "192k", "limited": True, "faststart": True,
            "hint": "H.265 4K. Smaller than H.264 at same quality. YouTube accepts HEVC.\n"
                    "✓ faststart enabled.",
        },
        "Discord / Web": {
            "res": "1080p (1920×1080)", "fmt": "mp4", "codec": "libx264", "crf": 26,
            "audio": "128k", "limited": True, "faststart": True,
            "hint": "H.264, good quality, smaller file. Plays directly in Discord and most browsers.\n"
                    "✓ faststart — starts playing immediately when linked.",
        },
        "Twitter / X": {
            "res": "720p (1280×720)", "fmt": "mp4", "codec": "libx264", "crf": 26,
            "audio": "128k", "limited": True, "faststart": True,
            "hint": "Twitter requires H.264 MP4 under 512 MB, max 2 min 20 sec. 720p recommended.\n"
                    "✓ faststart enabled.",
        },
        "Archive": {
            "res": "Original", "fmt": "mkv", "codec": "libx265", "crf": 16,
            "audio": "320k", "limited": False, "faststart": False,
            "hint": "Near-lossless H.265 MKV. Best for long-term storage or re-editing.\n"
                    "Full Range preserved. Large files.",
        },
    }

    CONV_RESOLUTIONS = {
        "Original":           None,
        "4K (3840×2160)":     "-2:2160",
        "1440p (2560×1440)":  "-2:1440",
        "1080p (1920×1080)":  "-2:1080",
        "720p (1280×720)":    "-2:720",
        "480p (852×480)":     "-2:480",
    }

    input_file_var  = ctk.StringVar()
    conv_out_var    = ctk.StringVar(value=str(get_path(
        "AUTOMATIONS_FFMPEG_CONVERT_DIR", default=Path.home() / "Videos")))
    conv_fmt_var    = ctk.StringVar(value="mp4")
    conv_codec_var  = ctk.StringVar(value="libx264")
    conv_crf_var    = ctk.IntVar(value=18)
    conv_res_var    = ctk.StringVar(value="1080p (1920×1080)")
    conv_audio_var  = ctk.StringVar(value="192k")
    conv_limited_var   = ctk.BooleanVar(value=True)
    conv_faststart_var = ctk.BooleanVar(value=True)
    conv_src_full_var  = ctk.BooleanVar(value=True)

    conv_preset_hint_label = None   # set after UI is built

    def _apply_conv_preset(name):
        p = CONV_PRESETS[name]
        conv_res_var.set(p["res"])
        conv_fmt_var.set(p["fmt"])
        conv_codec_var.set(p["codec"])
        conv_crf_var.set(p["crf"])
        conv_audio_var.set(p["audio"])
        conv_limited_var.set(p["limited"])
        conv_faststart_var.set(p["faststart"])
        _refresh_conv_crf()
        conv_preset_hint_label.configure(text=p["hint"])
        set_status(f'Convert preset "{name}" applied.', "#4CAF50")

    def _refresh_conv_crf(*_):
        v = conv_crf_var.get()
        conv_crf_num.configure(text=str(v))
        conv_crf_desc.configure(text=_crf_label(v))

    conv_crf_var.trace_add("write", _refresh_conv_crf)

    def _build_conv_cmd(in_f, out_f):
        scale   = CONV_RESOLUTIONS.get(conv_res_var.get())
        codec   = conv_codec_var.get()
        crf     = conv_crf_var.get()
        audio   = conv_audio_var.get()
        limited = conv_limited_var.get()
        fs      = conv_faststart_var.get()
        src_full = conv_src_full_var.get()

        cmd = ["ffmpeg", "-y", "-i", in_f]

        # Build vf — only if scale or colour correction needed
        in_range  = "full"    if src_full  else "limited"
        out_range = "limited" if limited   else "full"
        color_args = f"in_range={in_range}:out_range={out_range}:out_color_matrix=bt709"

        if scale:
            vf = f"scale={scale}:{color_args}:flags=lanczos"
        else:
            vf = f"scale=iw:ih:{color_args}"
        cmd += ["-vf", vf]

        # Video codec
        if codec in ("libx264", "libx265"):
            cmd += ["-vcodec", codec, "-crf", str(crf), "-preset", "medium",
                    "-pix_fmt", "yuv420p"]
        elif codec == "libvpx-vp9":
            cmd += ["-vcodec", "libvpx-vp9", "-crf", str(crf), "-b:v", "0",
                    "-pix_fmt", "yuv420p"]
        else:
            cmd += ["-vcodec", codec]

        # Colour metadata
        cmd += [
            "-colorspace",      "bt709",
            "-color_primaries", "bt709",
            "-color_trc",       "bt709",
            "-color_range",     "tv" if limited else "pc",
        ]

        # Audio
        fmt = conv_fmt_var.get()
        if fmt == "webm":
            cmd += ["-acodec", "libopus", "-b:a", audio]
        elif fmt == "avi":
            cmd += ["-acodec", "libmp3lame", "-b:a", audio]
        else:
            cmd += ["-acodec", "aac", "-b:a", audio]

        # Web optimisation: move moov atom to start so video streams immediately
        if fs and fmt in ("mp4", "mov"):
            cmd += ["-movflags", "+faststart"]

        cmd.append(out_f)
        return cmd

    def _browse_conv_input():
        p = filedialog.askopenfilename(
            title="Select Video File",
            filetypes=[("Video files", "*.mp4 *.mkv *.avi *.mov *.webm *.flv *.wmv *.ts"),
                       ("All files", "*.*")])
        if p:
            input_file_var.set(p)

    def _browse_conv_out():
        p = filedialog.askdirectory(title="Select Output Folder")
        if p:
            conv_out_var.set(p)

    def start_conversion():
        in_f  = input_file_var.get().strip()
        out_d = conv_out_var.get().strip()
        if not in_f or not os.path.isfile(in_f):
            messagebox.showwarning("No input file", "Please select a valid input video file.", parent=win)
            return
        if not out_d:
            messagebox.showwarning("No output folder", "Please select an output folder.", parent=win)
            return
        fmt   = conv_fmt_var.get()
        base  = os.path.splitext(os.path.basename(in_f))[0]
        out_f = os.path.join(out_d, f"{base}_web.{fmt}")
        cmd   = _build_conv_cmd(in_f, out_f)

        convert_btn.configure(state="disabled", text="Converting…")
        conv_progress.set(0)
        conv_result_label.configure(text="")
        set_status("Converting…", "#FFA500")

        def run():
            try:
                proc = subprocess.run(cmd, capture_output=True,
                                      creationflags=subprocess.CREATE_NO_WINDOW)
                ok = proc.returncode == 0
                err = proc.stderr.decode("utf-8", errors="replace") if not ok else ""
            except (OSError, subprocess.SubprocessError, ValueError) as e:
                ok, err = False, str(e)

            def done():
                conv_progress.set(1)
                convert_btn.configure(state="normal", text="Convert")
                if ok:
                    size_mb = os.path.getsize(out_f) / 1_048_576 if os.path.exists(out_f) else 0
                    set_status(f"Done  →  {os.path.basename(out_f)}  ({size_mb:.1f} MB)", "#4CAF50")
                    conv_result_label.configure(text=out_f)
                else:
                    set_status("Conversion failed — check settings.", "red")
                    conv_result_label.configure(text=err[-300:] if err else "Unknown error",
                                                text_color="#FF6B6B")
            win.after(0, done)

        threading.Thread(target=run, daemon=True).start()

    # ── Platform presets ─────────────────────────────────────────────────────
    cps = _section(ct, "Target Platform  (quick presets)")
    conv_btn_row = _row(cps)
    preset_palette = {
        "YouTube":      ("#b71c1c", "#7f0000"),
        "YouTube 4K":   ("#880e0e", "#600a0a"),
        "Discord / Web":("#1a4f8c", "#133b6e"),
        "Twitter / X":  ("#0d4f73", "#083a56"),
        "Archive":      ("#3a3a3a", "#222222"),
    }
    for name, (fg, hov) in preset_palette.items():
        ctk.CTkButton(conv_btn_row, text=name, width=126, height=32,
                      fg_color=fg, hover_color=hov,
                      command=lambda n=name: _apply_conv_preset(n)).pack(side="left", padx=3, pady=6)

    conv_preset_hint_label = ctk.CTkLabel(
        cps, text="Select a platform preset above, or configure options manually below.",
        font=ctk.CTkFont(size=10), text_color="#888888", wraplength=660, justify="left")
    conv_preset_hint_label.pack(anchor="w", padx=14, pady=(0, 8))

    # ── Files ────────────────────────────────────────────────────────────────
    cfs = _section(ct, "Files")
    r = _row(cfs)
    _label(r, "Input Video:")
    ctk.CTkEntry(r, textvariable=input_file_var, width=430).pack(side="left")
    ctk.CTkButton(r, text="Browse", width=80, command=_browse_conv_input).pack(side="left", padx=(6, 0))
    r = _row(cfs)
    _label(r, "Output Folder:")
    ctk.CTkEntry(r, textvariable=conv_out_var, width=430).pack(side="left")
    ctk.CTkButton(r, text="Browse", width=80, command=_browse_conv_out).pack(side="left", padx=(6, 0))
    _hint(cfs, "Output file will be named  originalname_web.mp4  (or .mkv / .webm depending on format).")

    # ── Video options ─────────────────────────────────────────────────────────
    cvs = _section(ct, "Video Options")

    r = _row(cvs)
    _label(r, "Output Format:")
    for fmt, lbl in [("mp4","MP4"), ("mkv","MKV"), ("webm","WebM"), ("mov","MOV")]:
        ctk.CTkRadioButton(r, text=lbl, variable=conv_fmt_var, value=fmt).pack(side="left", padx=(0, 14))
    _hint(cvs, "MP4 — best compatibility for web, YouTube, Discord, Twitter.\n"
               "MKV — great for archiving, supports all codecs, less compatible with web players.\n"
               "WebM — open format, very good for browser embedding.\n"
               "MOV — Apple ecosystem, iMovie compatible.")

    r = _row(cvs)
    _label(r, "Resolution:")
    ctk.CTkOptionMenu(r, variable=conv_res_var,
                      values=list(CONV_RESOLUTIONS.keys()), width=260).pack(side="left")
    _hint(cvs, "Original keeps the source resolution. Scaling down reduces file size significantly.\n"
               "Aspect ratio is preserved automatically — no stretching.")

    r = _row(cvs)
    _label(r, "Codec:")
    for val, lbl in [("libx264","H.264  (most compatible)"),
                     ("libx265","H.265  (better quality, smaller)"),
                     ("libvpx-vp9","VP9  (WebM)")]:
        ctk.CTkRadioButton(r, text=lbl, variable=conv_codec_var, value=val).pack(side="left", padx=(0, 12))
    _hint(cvs, "H.264 — plays everywhere: YouTube, Discord, Twitter, phones, TVs.\n"
               "H.265 — same quality at ~40% smaller file. Requires modern device/browser to play.\n"
               "VP9 — best for WebM format. Good browser support.")

    r = _row(cvs)
    _label(r, "Quality (CRF):")
    conv_q_slider = ctk.CTkSlider(r, from_=0, to=51, variable=conv_crf_var, width=250, number_of_steps=51)
    conv_q_slider.pack(side="left")
    conv_crf_num  = ctk.CTkLabel(r, text="18", width=28, font=ctk.CTkFont(weight="bold"))
    conv_crf_num.pack(side="left", padx=(8, 4))
    conv_crf_desc = ctk.CTkLabel(r, text=_crf_label(18), text_color="#4CAF50",
                                 font=ctk.CTkFont(size=11))
    conv_crf_desc.pack(side="left")
    _hint(cvs, "Lower = better quality and larger file. 18 is excellent for YouTube. 26–28 for Discord/social.\n"
               "Note: H.265 at CRF 22 ≈ H.264 at CRF 18 in visual quality (H.265 compresses better).")

    # ── Audio options ─────────────────────────────────────────────────────────
    cas = _section(ct, "Audio Options")
    r = _row(cas)
    _label(r, "Audio Bitrate:")
    for val, lbl in [("96k","96k  (small)"), ("128k","128k  (good)"),
                     ("192k","192k  (great ✓)"), ("320k","320k  (lossless-near)")]:
        ctk.CTkRadioButton(r, text=lbl, variable=conv_audio_var, value=val).pack(side="left", padx=(0, 10))
    _hint(cas, "192k AAC is the recommended sweet spot — transparent quality at reasonable size.\n"
               "320k for archiving or music-heavy content. 128k for social media clips.")

    # ── Colour & Web settings ─────────────────────────────────────────────────
    cws = _section(ct, "Colour & Web Settings")

    r = _row(cws)
    ctk.CTkCheckBox(r, text="Source is Full Range  (recorded with this tool / OBS / screen capture)",
                    variable=conv_src_full_var).pack(side="left")
    _hint(cws, "Enable if converting a recording made with FFmpeg Studio or any screen capture tool.\n"
               "This ensures colours are converted correctly and don't get washed out.")

    r = _row(cws)
    ctk.CTkCheckBox(r, text="Output Limited Range  (recommended for YouTube, Twitter, web)",
                    variable=conv_limited_var).pack(side="left")
    _hint(cws, "YouTube and most web platforms expect Limited Range (16–235). "
               "Disable only for archiving where Full Range should be preserved.")

    r = _row(cws)
    fs_chk = ctk.CTkCheckBox(r, text="Enable faststart  (strongly recommended for web videos)",
                              variable=conv_faststart_var)
    fs_chk.pack(side="left")
    _hint(cws, "Moves video metadata to the start of the file. This allows playback to begin immediately\n"
               "when shared on Discord, Twitter, or embedded on a website — without waiting for the full download.\n"
               "Only applies to MP4 and MOV.")

    # ── Convert controls ──────────────────────────────────────────────────────
    conv_ctrl = ctk.CTkFrame(ct, fg_color="#1e1e1e", corner_radius=10)
    conv_ctrl.pack(fill="x", padx=6, pady=(12, 8))

    conv_progress = ctk.CTkProgressBar(conv_ctrl, width=640)
    conv_progress.set(0)
    conv_progress.pack(padx=16, pady=(12, 4))

    convert_btn = ctk.CTkButton(
        conv_ctrl, text="Convert", width=200, height=42,
        font=ctk.CTkFont(size=14, weight="bold"),
        fg_color="#3a7ebf", hover_color="#2b6194",
        command=start_conversion,
    )
    convert_btn.pack(pady=(4, 6))

    conv_result_label = ctk.CTkLabel(conv_ctrl, text="", font=ctk.CTkFont(size=10),
                                     text_color="gray", wraplength=660)
    conv_result_label.pack(pady=(0, 8))

    # ── Status bar ────────────────────────────────────────────────────────────
    status_label = ctk.CTkLabel(win, text="Ready", font=ctk.CTkFont(size=11), text_color="gray")
    status_label.pack(side="bottom", pady=(0, 6))

    def on_close():
        if recording_proc is not None:
            stop_recording()
        win.destroy()

    win.protocol("WM_DELETE_WINDOW", on_close)
