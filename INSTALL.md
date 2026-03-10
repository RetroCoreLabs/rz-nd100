# Installing the rz-nd100 Plugins

This guide covers installing the rz-nd100 Rizin plugins from scratch on Linux and Windows.

For build prerequisites and compilation instructions, see [BUILD.md](BUILD.md).

---

## Plugins Overview

The rz-nd100 project builds and installs five plugins:

| Plugin | File (Linux / Windows) | Type | Purpose |
|--------|------------------------|------|---------|
| **asm_nd100** | `asm_nd100.so` / `asm_nd100.dll` | Assembler | Disassembles and assembles ND-100/ND-110 instructions, annotates MON calls and IOX registers |
| **analysis_nd100** | `analysis_nd100.so` / `analysis_nd100.dll` | Analysis | Control flow analysis, ESIL emulation, op classification, register definitions |
| **parse_nd100** | `parse_nd100.so` / `parse_nd100.dll` | Parser | C-like pseudo-code output for `pdc` and `asm.pseudo` |
| **bin_aout16** | `bin_aout16.so` / `bin_aout16.dll` | Binary loader | Loads ND-100 a.out16 executable and object files (symbols, relocations, segments, header) |
| **bin_bpun** | `bin_bpun.so` / `bin_bpun.dll` | Binary loader | Loads BPUN and FloMon bootstrap files |

All plugins are installed into Rizin's plugin directory automatically by the build system.

---

## Prerequisites

### Linux (Ubuntu/Debian)

Install Rizin from the RizinOrg OBS repository (Ubuntu 22.04):

```bash
echo 'deb http://download.opensuse.org/repositories/home:/RizinOrg/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/home:RizinOrg.list
curl -fsSL https://download.opensuse.org/repositories/home:RizinOrg/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_RizinOrg.gpg > /dev/null
sudo apt update
sudo apt install rizin librizin-dev
```

Install the build tools:

```bash
sudo apt install meson ninja-build
```

### Windows

1. Download and install **Rizin** from the official GitHub releases:
   <https://github.com/rizinorg/rizin/releases>

2. Download and install **Meson** from:
   <https://mesonbuild.com>

3. Ensure `ninja` is available. Meson ships with Ninja on Windows, or you can install it separately.

4. You will need a working C compiler -- either MSVC (via Visual Studio Build Tools) or MinGW.

See [BUILD.md](BUILD.md) for detailed prerequisite setup on both platforms.

---

## Installing Cutter (GUI)

### Linux

Install Cutter from the same RizinOrg OBS repository:

```bash
sudo apt install cutter-re
```

### Windows

Download the Cutter `.exe` installer from the official GitHub releases:
<https://github.com/rizinorg/cutter/releases>

Cutter on Windows is a native application and the recommended way to use the GUI.

---

## Building and Installing the Plugins

### Linux

```bash
git clone https://github.com/<your-org>/rz-nd100
cd rz-nd100
meson setup build
ninja -C build
sudo ninja -C build install
```

### Windows (Developer Command Prompt or PowerShell with MSVC/MinGW)

```powershell
git clone https://github.com/<your-org>/rz-nd100
cd rz-nd100
meson setup build
ninja -C build
ninja -C build install
```

> Replace `<your-org>` with the actual GitHub organization or username.

The install step copies all five plugins (`asm_nd100`, `analysis_nd100`, `parse_nd100`, `bin_aout16`, `bin_bpun`) into Rizin's plugin directory. The correct path is determined automatically via pkg-config.

---

## Verifying the Installation

### Disassembler and assembler plugin (asm_nd100)

```bash
rz-asm -L | grep nd100
```

Expected output:

```
adAe_ 16         nd100       LGPL3   Norsk Data ND-100/ND-110 disassembler and assembler (by Ronny Hansen) v1.0.1
```

The `A` flag confirms assembler support is available.

Quick assembler test:

```bash
rz-asm -a nd100 'LDA ,B -4'     # Should output: fc49
rz-asm -a nd100 -d fc49          # Should output: LDA ,B -4
```

### Analysis plugin (analysis_nd100)

```bash
rizin -qc "e asm.arch=nd100; aai" /dev/null 2>&1 | head -1
```

If no errors appear, the analysis plugin is loaded correctly.

### Parser plugin (parse_nd100)

```bash
rizin -qc "e asm.arch=nd100; e asm.pseudo=true; e asm.bits=16" /dev/null 2>&1
```

### Binary loader plugins (bin_aout16 and bin_bpun)

External plugins are not listed by `rz-bin -L`. Use Rizin's `iL` command instead:

```bash
rizin -qc 'iL' /dev/null | grep -E "aout16|bpun"
```

Expected output:

```
bin  aout16      Norsk Data ND-100 a.out16 format (LGPL3) 1.0.1 Ronny Hansen
bin  bpun        Norsk Data BPUN bootstrap format (LGPL3) 1.0.1 Ronny Hansen
```

### Using Cutter (GUI)

1. Open Cutter and load an ND-100 binary file (a.out16 or BPUN format).
2. Cutter should auto-detect the format via the `bin_aout16` or `bin_bpun` loader.
3. In the analysis options, select **nd100** as the architecture.
4. The disassembly view should display ND-100 instructions with MON call and IOX annotations.

---

## Uninstalling

### Linux

```bash
sudo ninja -C build uninstall
```

### Windows

```powershell
ninja -C build uninstall
```

This removes all five plugin files from Rizin's plugin directory.
