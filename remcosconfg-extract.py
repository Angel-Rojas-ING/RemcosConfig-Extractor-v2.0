#!/usr/bin/env python3
"""
RemcosConfig Extractor v2.0
Developed by Angel Gil && Jorge Gonzalez
Extracts and decrypts configuration from unpacked Remcos RAT samples.
Supports: Remcos v1.x - v4.x
"""

import json
import struct
import sys
import os
import hashlib
import math
import argparse
import csv
import re
from datetime import datetime

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

try:
    import pefile
except ImportError:
    print("[-] pefile required: pip install pefile")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init()
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = ""; GREEN = ""; YELLOW = ""; CYAN = ""
        MAGENTA = ""; WHITE = ""; BLUE = ""; RESET = ""
    class Style:
        BRIGHT = ""; DIM = ""; RESET_ALL = ""





VERSION = "2.0"

CONFIG_FIELDS = {
    0:  ("c2_hosts",            "network",       "C2 Hosts",               "c2"),
    1:  ("bot_name",            "identity",      "Bot Name / Campaign",    "string"),
    2:  ("connect_interval",    "network",       "Connect Interval (s)",   "int"),
    3:  ("install_flag",        "persistence",   "Install to System",      "flag"),
    4:  ("hkcu_run",            "persistence",   "HKCU\\Run Key",          "flag"),
    5:  ("hklm_run",            "persistence",   "HKLM\\Run Key",          "flag"),
    6:  ("startup_folder",      "persistence",   "Startup Folder",         "flag"),
    7:  ("sched_task",          "persistence",   "Scheduled Task",         "flag"),
    8:  ("task_trigger",        "persistence",   "Task Trigger",           "string"),
    9:  ("task_name",           "persistence",   "Task Name",              "string"),
    10: ("reg_key_name",        "persistence",   "Registry Key Name",      "string"),
    11: ("startup_value",       "persistence",   "Startup Value Name",     "string"),
    12: ("install_root",        "paths",         "Install Root",           "string"),
    13: ("install_subfolder",   "paths",         "Install Subfolder",      "string"),
    14: ("install_filename",    "paths",         "Install Filename",       "string"),
    15: ("keylog_flag",         "surveillance",  "Keylogger",              "flag"),
    16: ("keylog_encrypt",      "surveillance",  "Keylog Encryption",      "flag"),
    17: ("keylog_online",       "surveillance",  "Online Keylogger",       "flag"),
    18: ("screenshot_flag",     "surveillance",  "Screenshots",            "flag"),
    19: ("screenshot_interval", "surveillance",  "Screenshot Interval",    "int"),
    20: ("copy_filename",       "paths",         "Copy Filename",          "string"),
    21: ("clipboard_flag",      "surveillance",  "Clipboard Monitor",      "flag"),
    22: ("webcam_flag",         "surveillance",  "Webcam Capture",         "flag"),
    23: ("process_inject_flag", "evasion",       "Process Injection",      "flag"),
    24: ("uac_bypass_flag",     "evasion",       "UAC Bypass",             "flag"),
    25: ("watchdog_flag",       "evasion",       "Watchdog",               "flag"),
    26: ("defender_excl_flag",  "evasion",       "Defender Exclusion",     "flag"),
    27: ("hide_window_flag",    "evasion",       "Hide Window",            "flag"),
    28: ("mutex",               "identity",      "Mutex",                  "string"),
    29: ("tls_flag",            "network",       "TLS Enabled",            "flag"),
    30: ("tls_cert",            "network",       "TLS Certificate",        "string"),
    31: ("c2_password",         "network",       "C2 Password",            "string"),
    32: ("ping_interval",       "network",       "Ping Interval (s)",      "int"),
    33: ("max_packet_size",     "network",       "Max Packet Size",        "int"),
    34: ("keylog_filename",     "paths",         "Keylog Filename",        "string"),
    35: ("audio_flag",          "surveillance",  "Audio Capture",          "flag")
    36: ("audio_record_time",   "surveillance",  "Audio Record Time",      "int"),
    37: ("browser_stealer",     "surveillance",  "Browser Stealer",        "flag"),
    38: ("file_manager",        "surveillance",  "File Manager",           "flag"),
    39: ("screen_recorder",     "surveillance",  "Screen Recorder",        "flag"),
    40: ("rdp_wrapper",         "surveillance",  "RDP Wrapper",            "flag"),
    41: ("inj_target_1",        "evasion",       "Injection Target 1",     "string"),
    42: ("inj_target_2",        "evasion",       "Injection Target 2",     "string"),
    43: ("inj_target_3",        "evasion",       "Injection Target 3",     "string"),
    44: ("inj_target_4",        "evasion",       "Injection Target 4",     "string"),
    52: ("screenshots_dir",     "paths",         "Screenshots Directory",  "string"),
    76: ("audio_dir",           "paths",         "Audio Directory",        "string"),
    98: ("keylog_dir",          "paths",         "Keylog Directory",       "string"),
}

CATEGORIES = {
    "network":      ("NETWORK",       Fore.CYAN),
    "identity":     ("IDENTITY",      Fore.MAGENTA),
    "persistence":  ("PERSISTENCE",   Fore.YELLOW),
    "surveillance": ("SURVEILLANCE",  Fore.RED),
    "evasion":      ("EVASION",       Fore.RED),
    "paths":        ("PATHS & FILES", Fore.BLUE),
    "unknown":      ("OTHER FIELDS",  Fore.WHITE),
}

CATEGORY_ORDER = ["network", "identity", "persistence", "surveillance", "evasion", "paths", "unknown"]

BOX_WIDTH = 72   


_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _vis_len(text: str) -> int:
    """Visible length of a string (ANSI escape codes have zero width)."""
    return len(_ANSI_RE.sub('', text))


def _box_line_raw(content: str, border_color: str) -> str:
    """
    Wrap `content` (which may contain ANSI codes) into one or more lines,
    each framed with '|' borders so the visible text never exceeds BOX_WIDTH-2
    characters (one space padding on each side comes from the caller's indent).
    """
    # Usable visible width inside the box
    INNER = BOX_WIDTH - 2   # 70 chars

    r  = Style.RESET_ALL if HAS_COLOR else ""
    bc = border_color if border_color else ""

    # Walk through `content` char-by-char, accounting for ANSI codes.
    segments   = []   # finished lines (raw content strings, no borders yet)
    cur        = ""   # current line (with embedded ANSI)
    cur_vis    = 0    # visible length of `cur`

    i = 0
    while i < len(content):
        m = _ANSI_RE.match(content, i)
        if m:
            cur += m.group()
            i   += len(m.group())
            continue

        ch = content[i]
        i += 1

        if cur_vis < INNER:
            cur     += ch
            cur_vis += 1
        else:
            segments.append(cur)
            cur     = ch
            cur_vis = 1

    segments.append(cur)   # flush last chunk

    # Build output lines: pad each segment so the border lands in the right column
    out_lines = []
    for seg in segments:
        pad = " " * (INNER - _vis_len(seg))
        out_lines.append(f"  {bc}|{r} {seg}{pad} {bc}|{r}")

    return "\n".join(out_lines)





def box_top(title="", color=""):
    r = Fore.RESET if HAS_COLOR else ""
    if title:
        title_str = f" {title} "
        line = f"  {color}{Style.BRIGHT}+{'=' * BOX_WIDTH}+{Style.RESET_ALL}"
        return (
            line
            + f"\n  {color}{Style.BRIGHT}|{r}  "
            + f"{color}{Style.BRIGHT}{title_str:<{BOX_WIDTH - 2}}{color}|{Style.RESET_ALL}"
        )
    return f"  {color}+{'-' * BOX_WIDTH}+{Style.RESET_ALL}"


def box_line(text="", color="", indent=2):
    """
    Print one (or more, if wrapping) lines inside a box.
    `text` may contain ANSI colour codes.
    `color` is the border colour.
    `indent` is kept for API compatibility but wrap is always active.
    """
    return _box_line_raw(text, border_color=color)


def box_separator(color=""):
    r = Style.RESET_ALL if HAS_COLOR else ""
    return f"  {color}|{'-' * BOX_WIDTH}|{r}"


def box_bottom(color=""):
    return f"  {color}+{'-' * BOX_WIDTH}+{Style.RESET_ALL}"


def box_bottom_double(color=""):
    return f"  {color}{Style.BRIGHT}+{'=' * BOX_WIDTH}+{Style.RESET_ALL}"


def flag_str(value):
    if isinstance(value, (int, float)):
        is_on = value > 0
    elif isinstance(value, str):
        is_on = value.lower() in ("1", "true", "yes", "enabled", "on")
    elif isinstance(value, bool):
        is_on = value
    else:
        is_on = bool(value)

    if is_on:
        return f"{Fore.GREEN}{Style.BRIGHT}[ON] {Style.RESET_ALL}"
    else:
        return f"{Fore.RED}[OFF]{Style.RESET_ALL}"





def print_banner():
    c = Fore.CYAN if HAS_COLOR else ""
    r = Style.RESET_ALL if HAS_COLOR else ""
    y = Fore.YELLOW if HAS_COLOR else ""
    w = Fore.WHITE if HAS_COLOR else ""
    b = Style.BRIGHT if HAS_COLOR else ""
    d = Style.DIM if HAS_COLOR else ""

    banner = f"""
  {c}{b}+========================================================================+
  |                                                                        |
  |{r}  {c} ____                               ____             __ _            {c}{b}|
  |{r}  {c}|  _ \\ ___ _ __ ___   ___ ___  ___ / ___|___  _ __  / _(_) __ _     {c}{b}|
  |{r}  {c}| |_) / _ \\ '_ ` _ \\ / __/ _ \\/ __| |   / _ \\| '_ \\| |_| |/ _` |   {c}{b}|
  |{r}  {c}|  _ <  __/ | | | | | (_| (_) \\__ \\ |__| (_) | | | |  _| | (_| |   {c}{b}|
  |{r}  {c}|_| \\_\\___|_| |_| |_|\\___\\___/|___/\\____\\___/|_| |_|_| |_|\\__, |   {c}{b}|
  |{r}  {c}                                                            |___/    {c}{b}|
  |                                                                              |
  |{r}  {y}{b}               E X T R A C T O R   v{VERSION}                         {c}{b}|
  |                                                                        |
  |{r}  {w}{d}   Developed by Angel Gil && Jorge Gonzalez                        {c}{b}|
  |                                                                        |
  +========================================================================+{r}
"""
    print(banner)





def rc4_decrypt(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]

    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)





def calculate_hashes(filepath: str) -> dict:
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        data = f.read()
        md5.update(data)
        sha1.update(data)
        sha256.update(data)
    return {
        "md5":    md5.hexdigest(),
        "sha1":   sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size":   len(data),
    }


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq    = [0] * 256
    for byte in data:
        freq[byte] += 1
    length  = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def detect_packer(filepath: str) -> str:
    try:
        pe = pefile.PE(filepath)
    except Exception:
        return "Error loading PE"

    packers = []
    for section in pe.sections:
        name    = section.Name.decode("utf-8", errors="replace").strip("\x00")
        entropy = calculate_entropy(section.get_data())
        if entropy > 7.2:
            packers.append(f"High entropy section: {name} ({entropy:.2f})")

    section_names = [
        s.Name.decode("utf-8", errors="replace").strip("\x00").lower()
        for s in pe.sections
    ]
    if "upx0" in section_names or "upx1" in section_names:
        packers.append("UPX")
    if ".themida" in section_names:
        packers.append("Themida")
    if ".vmp" in section_names or ".vmp0" in section_names:
        packers.append("VMProtect")
    if "aspack" in section_names:
        packers.append("ASPack")
    if ".ndata" in section_names:
        packers.append("NSIS Installer")

    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset:
        overlay_size = os.path.getsize(filepath) - overlay_offset
        if overlay_size > 1024:
            packers.append(f"Overlay data ({overlay_size:,} bytes)")

    pe.close()
    return ", ".join(packers) if packers else "None detected"


def detect_remcos_version(filepath: str) -> str:
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        for pattern in [b"Remcos v", b"Remcos_v", b"remcos v"]:
            idx = data.find(pattern)
            if idx != -1:
                version_str = ""
                for b in data[idx:idx + 30]:
                    if 0x20 <= b <= 0x7E:
                        version_str += chr(b)
                    else:
                        break
                if version_str:
                    return version_str

        pe = pefile.PE(filepath)
        if hasattr(pe, "VS_FIXEDFILEINFO"):
            ffi   = pe.VS_FIXEDFILEINFO[0]
            major = (ffi.FileVersionMS >> 16) & 0xFFFF
            minor =  ffi.FileVersionMS        & 0xFFFF
            build = (ffi.FileVersionLS >> 16) & 0xFFFF
            if major > 0:
                return f"v{major}.{minor}.{build}"
        pe.close()
    except Exception:
        pass
    return "Unknown"





def extract_settings_resource(filepath: str) -> bytes:
    pe        = pefile.PE(filepath)
    RT_RCDATA = 10

    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        raise ValueError("PE has no resource directory")

    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if res_type.id == RT_RCDATA or (
            res_type.name and str(res_type.name).upper() == "RCDATA"
        ):
            for res_name in res_type.directory.entries:
                name = str(res_name.name) if res_name.name else ""
                if "SETTINGS" in name.upper() or "SETTING" in name.upper():
                    for res_lang in res_name.directory.entries:
                        data_rva = res_lang.data.struct.OffsetToData
                        size     = res_lang.data.struct.Size
                        data     = pe.get_data(data_rva, size)
                        pe.close()
                        return data

    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if res_type.id == RT_RCDATA or (
            res_type.name and str(res_type.name).upper() == "RCDATA"
        ):
            for res_name in res_type.directory.entries:
                for res_lang in res_name.directory.entries:
                    data_rva = res_lang.data.struct.OffsetToData
                    size     = res_lang.data.struct.Size
                    data     = pe.get_data(data_rva, size)
                    if 50 < size < 10000:
                        pe.close()
                        return data

    pe.close()
    raise ValueError("Cannot locate RCDATA/SETTINGS resource in PE")





def parse_c2_hosts(raw_value):
    c2_list = []
    entries = raw_value if isinstance(raw_value, list) else [raw_value]
    for entry in entries:
        if isinstance(entry, str) and ":" in entry:
            parts = entry.split(":")
            c2    = {"host": parts[0]}
            if len(parts) > 1:
                c2["port"] = parts[1]
            c2["password"] = parts[2] if len(parts) > 2 and parts[2] else "(none)"
            c2_list.append(c2)
        else:
            c2_list.append({"raw": str(entry)})
    return c2_list


def remcos_decrypt_config(filepath: str) -> dict:
    settings = extract_settings_resource(filepath)

    key_length = settings[0]
    key        = settings[1: 1 + key_length]
    decrypted  = rc4_decrypt(settings[1 + key_length:], key)

    res = {
        "_rc4_key_hex":    key.hex(),
        "_rc4_key_ascii":  key.decode("ascii", errors="replace"),
        "_rc4_key_length": key_length,
        "_raw_fields":     {},
    }

    for i, val in enumerate(decrypted.split(b"|")):
        field_info = CONFIG_FIELDS.get(i)

        if val in (b"\x1e\x1e\x1f", b"\x00", b""):
            continue

        vals   = val.split(b"\x1e") if b"\x1e" in val else [val]
        values = []

        for v in vals:
            if not v:
                continue
            value = None

            if value is None and b"\x00" not in v[:-1]:
                try:
                    value = v[:-1].decode("ascii") if v.endswith(b"\x00") else v.decode("ascii")
                except Exception:
                    pass

            if value is None and len(v) > 4:
                try:
                    value = v[:-2].decode("utf-16-le") if v.endswith(b"\x00\x00") else v.decode("utf-16-le")
                except Exception:
                    pass

            if value is None and len(v) == 4:
                value, = struct.unpack("<I", v)
            if value is None and len(v) == 2:
                value, = struct.unpack("<H", v)
            if value is None and len(v) == 1:
                value, = struct.unpack("<B", v)
            if value is None:
                value = v.hex()
            if value is not None:
                values.append(value)

        if not values:
            continue

        final_value = values[0] if len(values) == 1 else values

        if field_info:
            field_name, category, display_name, field_type = field_info
            res[field_name] = final_value
            res["_raw_fields"][i] = {
                "name":     field_name,
                "category": category,
                "display":  display_name,
                "type":     field_type,
                "value":    final_value,
                "index":    i,
            }
        else:
            field_name = f"FIELD_{i}"
            res[field_name] = final_value
            res["_raw_fields"][i] = {
                "name":     field_name,
                "category": "unknown",
                "display":  f"Unknown Field {i}",
                "type":     "string",
                "value":    final_value,
                "index":    i,
            }

    return res





def print_sample_info(filepath, hashes, packer_info, remcos_version):
    c = Fore.CYAN
    w = Fore.WHITE
    y = Fore.YELLOW
    r = Style.RESET_ALL

    filename = os.path.basename(filepath)

    print(box_top("SAMPLE INFO", c))
    print(box_line(f"{w}File      : {Style.BRIGHT}{filename}{r}",                          color=c))
    print(box_line(f"{w}SHA-256   : {y}{hashes['sha256']}{r}",                             color=c))
    print(box_line(f"{w}MD5       : {y}{hashes['md5']}{r}",                                color=c))
    print(box_line(f"{w}SHA-1     : {y}{hashes['sha1']}{r}",                               color=c))
    print(box_line(f"{w}Size      : {w}{hashes['size']:,} bytes{r}",                       color=c))
    print(box_line(f"{w}Packer    : {w}{packer_info}{r}",                                  color=c))
    print(box_line(f"{w}Remcos    : {Fore.GREEN}{Style.BRIGHT}{remcos_version}{r}",        color=c))
    print(box_bottom_double(c))
    print()


def print_rc4_info(config):
    c = Fore.MAGENTA
    y = Fore.YELLOW
    w = Fore.WHITE
    r = Style.RESET_ALL

    print(box_top("RC4 KEY", c))
    print(box_line(f"{w}Hex       : {y}{config['_rc4_key_hex']}{r}",    color=c))
    print(box_line(f"{w}ASCII     : {y}{config['_rc4_key_ascii']}{r}",  color=c))
    print(box_line(f"{w}Length    : {w}{config['_rc4_key_length']} bytes{r}", color=c))
    print(box_bottom(c))
    print()


def print_category_box(category_key, fields, config):
    if not fields:
        return

    cat_display, cat_color = CATEGORIES.get(category_key, (category_key.upper(), Fore.WHITE))
    r = Style.RESET_ALL
    w = Fore.WHITE

    print(box_top(cat_display, cat_color))

    for field in fields:
        display_name = field["display"]
        value        = field["value"]
        field_type   = field["type"]

        if field_type == "c2":
            c2_list = parse_c2_hosts(value)
            for idx, c2 in enumerate(c2_list, 1):
                if "raw" in c2:
                    print(box_line(
                        f"{Fore.RED}{Style.BRIGHT}[C2 #{idx}]  {c2['raw']}{r}",
                        color=cat_color
                    ))
                else:
                    host = c2.get("host", "?")
                    port = c2.get("port", "?")
                    pwd  = c2.get("password", "(none)")
                    print(box_line(
                        f"{Fore.RED}{Style.BRIGHT}[C2 #{idx}]  {host}:{port}  "
                        f"{Style.DIM}(password: {pwd}){r}",
                        color=cat_color
                    ))

        elif field_type == "flag":
            flag = flag_str(value)
            print(box_line(f"{w}{display_name:<22} {flag}{r}", color=cat_color))

        elif field_type == "int":
            val_str = ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)
            print(box_line(f"{w}{display_name:<22} : {Fore.YELLOW}{val_str}{r}", color=cat_color))

        else:
            val_str = ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)
            print(box_line(f"{w}{display_name:<22} : {Fore.YELLOW}{val_str}{r}", color=cat_color))

    print(box_bottom(cat_color))
    print()


def print_config(config):
    raw_fields = config.get("_raw_fields", {})
    for category_key in CATEGORY_ORDER:
        fields = [f for f in raw_fields.values() if f["category"] == category_key]
        if fields:
            fields.sort(key=lambda x: x["index"])
            print_category_box(category_key, fields, config)


def print_summary(all_configs, all_hashes):
    c = Fore.GREEN
    y = Fore.YELLOW
    w = Fore.WHITE
    r = Style.RESET_ALL

    if len(all_configs) < 2:
        return

    unique_c2        = set()
    unique_mutex     = set()
    unique_rc4       = set()
    unique_campaigns = set()

    for config in all_configs:
        if "c2_hosts" in config:
            for c2 in parse_c2_hosts(config["c2_hosts"]):
                unique_c2.add(f"{c2['host']}:{c2.get('port', '?')}" if "host" in c2 else c2["raw"])
        if "mutex" in config:
            unique_mutex.add(str(config["mutex"]))
        unique_rc4.add(config.get("_rc4_key_hex", ""))
        if "bot_name" in config:
            unique_campaigns.add(str(config["bot_name"]))

    print()
    print(box_top("BATCH SUMMARY", c))
    print(box_line(f"{w}Samples processed   : {y}{len(all_configs)}{r}", color=c))
    print(box_line(f"{w}Unique C2 servers   : {y}{len(unique_c2)}{r}",   color=c))
    for item in sorted(unique_c2):
        print(box_line(f"{Fore.RED}  >> {item}{r}", color=c))
    print(box_line(f"{w}Unique mutexes      : {y}{len(unique_mutex)}{r}", color=c))
    for mx in sorted(unique_mutex):
        print(box_line(f"{Fore.MAGENTA}  >> {mx}{r}", color=c))
    print(box_line(f"{w}Unique RC4 keys     : {y}{len(unique_rc4)}{r}",  color=c))
    for rk in sorted(unique_rc4):
        print(box_line(f"{Fore.CYAN}  >> {rk}{r}", color=c))
    if unique_campaigns:
        print(box_line(f"{w}Campaigns detected  : {y}{len(unique_campaigns)}{r}", color=c))
        for camp in sorted(unique_campaigns):
            print(box_line(f"{Fore.YELLOW}  >> {camp}{r}", color=c))
    print(box_bottom_double(c))
    print()





def export_csv(all_configs, all_hashes, output_file):
    if not all_configs:
        return
    all_field_names = set()
    for config in all_configs:
        for key in config:
            if not key.startswith("_"):
                all_field_names.add(key)
    field_names = ["filename", "sha256", "md5", "rc4_key"] + sorted(all_field_names)
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=field_names)
        writer.writeheader()
        for config, hashes in zip(all_configs, all_hashes):
            row = {
                "filename": hashes.get("filename", ""),
                "sha256":   hashes.get("sha256",   ""),
                "md5":      hashes.get("md5",       ""),
                "rc4_key":  config.get("_rc4_key_hex", ""),
            }
            for key in all_field_names:
                val = config.get(key)
                row[key] = " | ".join(str(v) for v in val) if isinstance(val, list) else (str(val) if val is not None else "")
            writer.writerow(row)
    print(f"  {Fore.GREEN}[+] CSV exported to: {output_file}{Style.RESET_ALL}")


def export_json(all_configs, all_hashes, output_file):
    output = []
    for config, hashes in zip(all_configs, all_hashes):
        output.append({
            "file":         hashes.get("filename", ""),
            "hashes":       {"sha256": hashes.get("sha256", ""), "md5": hashes.get("md5", ""), "sha1": hashes.get("sha1", "")},
            "rc4_key":       config.get("_rc4_key_hex",   ""),
            "rc4_key_ascii": config.get("_rc4_key_ascii", ""),
            "config":        {k: v for k, v in config.items() if not k.startswith("_")},
        })
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)
    print(f"  {Fore.GREEN}[+] JSON exported to: {output_file}{Style.RESET_ALL}")





def process_sample(filepath):
    hashes             = calculate_hashes(filepath)
    hashes["filename"] = os.path.basename(filepath)
    packer_info        = detect_packer(filepath)
    remcos_version     = detect_remcos_version(filepath)

    print_sample_info(filepath, hashes, packer_info, remcos_version)
    config = remcos_decrypt_config(filepath)
    print_rc4_info(config)
    print_config(config)
    return config, hashes


def main():
    parser = argparse.ArgumentParser(
        description="RemcosConfig Extractor v2.0 - Extract config from Remcos RAT samples",
        epilog="Developed by Angel Gil && Jorge Gonzalez | HACKCON_RD 2026",
    )
    parser.add_argument("files", nargs="+", help="Path to unpacked Remcos PE samples")
    parser.add_argument("--json",      metavar="FILE", help="Export results to JSON file")
    parser.add_argument("--csv",       metavar="FILE", help="Export results to CSV file")
    parser.add_argument("--no-banner", action="store_true", help="Skip ASCII art banner")
    parser.add_argument("--no-color",  action="store_true", help="Disable colored output")
    args = parser.parse_args()

    global HAS_COLOR
    if args.no_color:
        HAS_COLOR = False
        Fore.RED = Fore.GREEN = Fore.YELLOW = Fore.CYAN = ""
        Fore.MAGENTA = Fore.WHITE = Fore.BLUE = Fore.RESET = ""
        Style.BRIGHT = Style.DIM = Style.RESET_ALL = ""

    if not args.no_banner:
        print_banner()

    all_configs = []
    all_hashes  = []
    total       = len(args.files)

    for idx, filepath in enumerate(args.files, 1):
        if total > 1:
            pct     = int((idx / total) * 100)
            bar_len = 30
            filled  = int(bar_len * idx / total)
            bar     = f"{'#' * filled}{'-' * (bar_len - filled)}"
            print(f"\n  {Fore.CYAN}[{bar}] {pct}% ({idx}/{total}) Processing...{Style.RESET_ALL}\n")

        try:
            config, hashes = process_sample(filepath)
            all_configs.append(config)
            all_hashes.append(hashes)
        except Exception as e:
            print(f"\n  {Fore.RED}[ERROR] {filepath}: {e}{Style.RESET_ALL}\n", file=sys.stderr)

    print_summary(all_configs, all_hashes)

    if args.csv  and all_configs:
        export_csv(all_configs, all_hashes, args.csv)
    if args.json and all_configs:
        export_json(all_configs, all_hashes, args.json)

    print(f"  {Style.DIM}Completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
