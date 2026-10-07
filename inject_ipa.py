#!/usr/bin/env python3
"""
inject_ipa.py
Reads the Twitch IPA, adds the compiled dylib to Frameworks/,
injects an LC_LOAD_DYLIB load command into the Twitch Mach-O binary,
and repacks into a new IPA ready for sideloading.

Usage:
    python3 inject_ipa.py <input.ipa> <TwitchAdBlock.dylib> [output.ipa]
"""

import struct
import sys
import zipfile
import os
import tempfile
import plistlib

# Mach-O constants
MH_MAGIC_64          = 0xFEEDFACF
MH_CIGAM_64          = 0xCFFAEDFE
LC_LOAD_DYLIB        = 0x0000000C
LC_ENCRYPTION_INFO   = 0x00000021  # 32-bit
LC_ENCRYPTION_INFO_64 = 0x0000002C # 64-bit
DYLIB_INSTALL_NAME   = None  # set at runtime from dylib filename


def align_up(n, align):
    return (n + align - 1) & ~(align - 1)


def clear_cryptid(binary: bytes) -> bytes:
    """Zero out cryptid in LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 so dyld doesn't re-decrypt."""
    magic = struct.unpack_from("<I", binary)[0]
    if magic != MH_MAGIC_64:
        return binary

    hdr_fmt  = "<8I"
    hdr_size = struct.calcsize(hdr_fmt)
    _, _, _, _, ncmds, _, _, _ = struct.unpack_from(hdr_fmt, binary)

    out = bytearray(binary)
    pos = hdr_size
    patched = 0
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", binary, pos)
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            # encryption_info_command: cmd(4) cmdsize(4) cryptoff(4) cryptsize(4) cryptid(4)
            cryptid_offset = pos + 16
            cryptid = struct.unpack_from("<I", binary, cryptid_offset)[0]
            if cryptid != 0:
                struct.pack_into("<I", out, cryptid_offset, 0)
                print(f"  Cleared cryptid ({cryptid} -> 0) in load command at offset {pos:#x}")
                patched += 1
            else:
                print(f"  cryptid already 0 at offset {pos:#x} — no change needed")
        pos += size

    if patched == 0 and not any(
        struct.unpack_from("<II", binary, p)[0] in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64)
        for p in _cmd_offsets(binary, ncmds, hdr_size)
    ):
        print("  No LC_ENCRYPTION_INFO found — binary may already be fully decrypted")

    return bytes(out)


def _cmd_offsets(binary, ncmds, start):
    pos = start
    for _ in range(ncmds):
        yield pos
        size = struct.unpack_from("<I", binary, pos + 4)[0]
        pos += size


def inject_load_dylib(binary: bytes, install_name: bytes) -> bytes:
    """Add LC_LOAD_DYLIB for the given install name to a single-arch arm64 Mach-O."""
    magic = struct.unpack_from("<I", binary)[0]
    if magic != MH_MAGIC_64:
        raise ValueError(f"Not a 64-bit little-endian Mach-O (magic={magic:#010x})")

    # Parse header
    # struct mach_header_64: magic cputype cpusubtype filetype ncmds sizeofcmds flags reserved
    hdr_fmt  = "<8I"
    hdr_size = struct.calcsize(hdr_fmt)  # 32 bytes
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = \
        struct.unpack_from(hdr_fmt, binary)

    load_cmds_start = hdr_size
    load_cmds_end   = load_cmds_start + sizeofcmds

    # Build new LC_LOAD_DYLIB command
    name_bytes = install_name
    name_padded = name_bytes + b"\x00" * (align_up(len(name_bytes), 8) - len(name_bytes))
    # dylib_command header: cmd(4) + cmdsize(4) + name.offset(4) + timestamp(4)
    #                        + current_version(4) + compatibility_version(4) = 24 bytes
    dylib_hdr_size = 24
    cmd_size = dylib_hdr_size + len(name_padded)
    cmd_size = align_up(cmd_size, 8)

    new_cmd = struct.pack("<IIIII",
        LC_LOAD_DYLIB,
        cmd_size,
        dylib_hdr_size,  # name offset from start of command
        0,               # timestamp
        0x00010000,      # current_version (1.0)
    )
    new_cmd += struct.pack("<I", 0x00010000)  # compatibility_version
    new_cmd += name_padded
    # Pad to cmd_size
    new_cmd += b"\x00" * (cmd_size - len(new_cmd))
    assert len(new_cmd) == cmd_size

    # Free space = gap between end of load commands and start of the first section's
    # actual file content. On iOS MH_EXECUTE binaries the __TEXT segment fileoff is 0
    # (load commands live inside it), so we must look at section offsets, not segment offsets.
    first_section_fileoff = None
    pos = load_cmds_start
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", binary, pos)
        if cmd == 0x19:  # LC_SEGMENT_64 — header is 72 bytes, then nsects * 80-byte section_64
            nsects = struct.unpack_from("<I", binary, pos + 64)[0]
            for i in range(nsects):
                # section_64.offset is a uint32_t at byte 48 within section_64
                sect_base = pos + 72 + i * 80
                sect_off  = struct.unpack_from("<I", binary, sect_base + 48)[0]
                if sect_off > 0:
                    if first_section_fileoff is None or sect_off < first_section_fileoff:
                        first_section_fileoff = sect_off
        pos += size

    if first_section_fileoff is None:
        raise ValueError("Could not find any section file offsets")

    free_space = first_section_fileoff - load_cmds_end
    print(f"  Load commands end at offset  {load_cmds_end:#x}")
    print(f"  First section content at     {first_section_fileoff:#x}")
    print(f"  Free space available:       {free_space} bytes")
    print(f"  New LC_LOAD_DYLIB size:     {cmd_size} bytes")

    if free_space < cmd_size:
        raise RuntimeError(
            f"Not enough free space ({free_space}B) to inject {cmd_size}B load command. "
            "This binary is too tightly packed — try a different Twitch version."
        )

    # Check the dylib isn't already injected
    existing = binary[load_cmds_start:load_cmds_end]
    dylib_name_short = install_name.rstrip(b"\x00").split(b"/")[-1]
    if dylib_name_short in existing:
        print(f"  {dylib_name_short.decode(errors='replace')} already present — skipping injection.")
        return binary

    # Patch: insert new command right after existing load commands, update header
    out = bytearray(binary)

    # Write new command into the free space
    out[load_cmds_end:load_cmds_end + cmd_size] = new_cmd

    # Update ncmds and sizeofcmds in the header
    new_ncmds      = ncmds + 1
    new_sizeofcmds = sizeofcmds + cmd_size
    struct.pack_into("<I", out, 16, new_ncmds)
    struct.pack_into("<I", out, 20, new_sizeofcmds)

    print(f"  Injected LC_LOAD_DYLIB (ncmds {ncmds} -> {new_ncmds}, "
          f"sizeofcmds {sizeofcmds} -> {new_sizeofcmds})")
    return bytes(out)


def patch_ats(plist_path: str) -> None:
    """Set NSAppTransportSecurity.NSAllowsArbitraryLoads = True so the tweak
    can route playlist requests through plain-HTTP proxies. iOS otherwise
    blocks any non-HTTPS NSURLSession traffic and the proxy ping fails with
    a -1 ATS error."""
    with open(plist_path, "rb") as f:
        data = f.read()
    fmt = plistlib.FMT_BINARY if data.startswith(b"bplist") else plistlib.FMT_XML
    plist = plistlib.loads(data)
    ats = plist.get("NSAppTransportSecurity", {})
    if ats.get("NSAllowsArbitraryLoads") is True:
        print("  NSAllowsArbitraryLoads already True — no change")
        return
    ats["NSAllowsArbitraryLoads"] = True
    plist["NSAppTransportSecurity"] = ats
    with open(plist_path, "wb") as f:
        plistlib.dump(plist, f, fmt=fmt)
    print(f"  Set NSAppTransportSecurity.NSAllowsArbitraryLoads = True")


FAT_MAGIC    = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
CPU_TYPE_ARM64 = 0x0100000C


def patch_macho(binary: bytes, install_name: bytes) -> bytes:
    """Clear cryptid and inject LC_LOAD_DYLIB. Handles thin arm64 binaries and
    fat (universal) binaries, in which case every arm64 slice is patched."""
    magic = struct.unpack_from(">I", binary)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return inject_load_dylib(clear_cryptid(binary), install_name)

    is64 = magic == FAT_MAGIC_64
    nfat = struct.unpack_from(">I", binary, 4)[0]
    arch_fmt = ">iiQQI4x" if is64 else ">iiIII"
    arch_size = struct.calcsize(arch_fmt)
    out = bytearray(binary)
    patched_any = False
    for i in range(nfat):
        cputype, _, offset, size, _ = struct.unpack_from(arch_fmt, binary, 8 + i * arch_size)
        if cputype != CPU_TYPE_ARM64:
            print(f"  Skipping non-arm64 slice (cputype {cputype:#x})")
            continue
        print(f"  Patching arm64 slice at offset {offset:#x}")
        slice_data = inject_load_dylib(clear_cryptid(binary[offset:offset + size]), install_name)
        assert len(slice_data) == size
        out[offset:offset + size] = slice_data
        patched_any = True
    if not patched_any:
        raise RuntimeError("Fat binary has no arm64 slice")
    return bytes(out)


def unix_mode(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0xFFFF


def make_info(name: str, template: zipfile.ZipInfo = None, mode: int = 0o100644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=template.date_time if template else (2020, 1, 1, 0, 0, 0))
    info.create_system = 3  # Unix, so the permission bits below are honoured
    info.external_attr = ((unix_mode(template) if template and unix_mode(template) else mode) << 16)
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    ipa_path  = sys.argv[1]
    dylib_src = sys.argv[2]
    out_path  = sys.argv[3] if len(sys.argv) > 3 else ipa_path.replace(".ipa", "-patched.ipa")

    if not os.path.isfile(dylib_src):
        raise SystemExit(f"Dylib not found: {dylib_src} (did `make SIDELOADED=1` succeed?)")

    print(f"[1/6] Reading IPA: {ipa_path}")
    zin = zipfile.ZipFile(ipa_path, "r")
    infos = zin.infolist()

    # Find app bundle name — entries look like "Payload/Twitch.app/somefile"
    app_name = None
    for info in infos:
        parts = info.filename.split("/")
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            app_name = parts[1]  # e.g. "Twitch.app"
            break
    if not app_name:
        raise RuntimeError("Could not find .app bundle in IPA")

    app_prefix = f"Payload/{app_name}/"
    info_plist_zip_path = app_prefix + "Info.plist"
    try:
        info_plist_data = zin.read(info_plist_zip_path)
    except KeyError:
        info_plist_data = None
    binary_name = app_name[:-len(".app")]
    if info_plist_data:
        binary_name = plistlib.loads(info_plist_data).get("CFBundleExecutable", binary_name)

    dylib_fname  = os.path.basename(dylib_src)   # e.g. "TwitchAdBlock.dylib"
    install_name = f"@executable_path/Frameworks/{dylib_fname}".encode() + b"\x00"

    binary_zip_path = app_prefix + binary_name
    dylib_zip_path  = app_prefix + "Frameworks/" + dylib_fname

    print(f"  App bundle  : {app_name}")
    print(f"  Binary path : {binary_zip_path}")
    print(f"  Dylib name  : {dylib_fname}")

    print(f"[2/6] Patching Mach-O binary...")
    try:
        binary_info = zin.getinfo(binary_zip_path)
    except KeyError:
        raise RuntimeError(f"Main executable {binary_zip_path} not found in IPA")
    patched_binary = patch_macho(zin.read(binary_info), install_name)

    print(f"[3/6] Patching Info.plist (ATS bypass for plain-HTTP proxy)...")
    patched_plist = None
    if info_plist_data:
        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as tmp:
            tmp.write(info_plist_data)
        try:
            patch_ats(tmp.name)
            with open(tmp.name, "rb") as f:
                patched_plist = f.read()
        finally:
            os.unlink(tmp.name)
    else:
        print(f"  WARNING: {info_plist_zip_path} not found — proxy routing will fail with ATS errors")

    # Localization bundle (optional — the settings UI falls back to English without it)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bundle_src = os.path.join(script_dir, "layout", "Library", "Application Support", "TwitchAdBlock.bundle")
    bundle_zip_prefix = app_prefix + "TwitchAdBlock.bundle/"

    replaced = {binary_zip_path: patched_binary, dylib_zip_path: None, info_plist_zip_path: patched_plist}

    print(f"[4/6] Copying dylib -> {dylib_zip_path}")
    print(f"[5/6] Copying localization bundle -> {bundle_zip_prefix}" if os.path.isdir(bundle_src)
          else "[5/6] Localization bundle not found — skipping")
    print(f"[6/6] Repacking IPA -> {out_path}")
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zout:
        # Copy every original entry, keeping its metadata (Unix permissions,
        # symlinks inside frameworks). Extracting to disk with zipfile would drop
        # the executable bits and break the app on install/launch.
        for info in infos:
            name = info.filename
            if name.startswith(bundle_zip_prefix) or name == dylib_zip_path:
                continue
            if name in replaced:
                if replaced[name] is not None:
                    zout.writestr(make_info(name, info), replaced[name])
                continue
            zout.writestr(info, zin.read(info), compress_type=info.compress_type)

        with open(dylib_src, "rb") as f:
            zout.writestr(make_info(dylib_zip_path, mode=0o100755), f.read())

        if os.path.isdir(bundle_src):
            for root, _, files in os.walk(bundle_src):
                for file in files:
                    fpath = os.path.join(root, file)
                    rel = os.path.relpath(fpath, bundle_src).replace(os.sep, "/")
                    with open(fpath, "rb") as f:
                        zout.writestr(make_info(bundle_zip_prefix + rel), f.read())
    zin.close()

    print(f"\nDone! Patched IPA: {out_path}")
    print("\nNext steps:")
    print("  AltStore / SideStore : drag the IPA into AltStore to install & sign")
    print("  TrollStore           : open the IPA in TrollStore to install")


if __name__ == "__main__":
    main()
