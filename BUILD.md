# Building rz-nd100

This document describes how to set up a build environment and compile the rz-nd100 plugins on Linux and Windows.

For installation of the compiled plugins into Rizin, see [INSTALL.md](INSTALL.md).

---

## What Gets Built

The build produces four shared library plugins:

| Plugin | File (Linux / Windows) | Purpose |
|--------|------------------------|---------|
| **asm_nd100** | `asm_nd100.so` / `asm_nd100.dll` | Disassembler for ND-100/ND-110 instructions |
| **analysis_nd100** | `analysis_nd100.so` / `analysis_nd100.dll` | Control flow and register analysis |
| **bin_aout16** | `bin_aout16.so` / `bin_aout16.dll` | Binary loader for ND-100 a.out16 executables and object files |
| **bin_bpun** | `bin_bpun.so` / `bin_bpun.dll` | Binary loader for BPUN bootstrap files |

All four plugins are installed into Rizin's plugin directory automatically.

---

## Prerequisites

### Linux (Ubuntu/Debian)

#### 1. Add the RizinOrg repository (Ubuntu 22.04)

```bash
echo 'deb http://download.opensuse.org/repositories/home:/RizinOrg/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/home:RizinOrg.list
curl -fsSL https://download.opensuse.org/repositories/home:RizinOrg/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_RizinOrg.gpg > /dev/null
sudo apt update
```

#### 2. Install Rizin and development headers

```bash
sudo apt install rizin librizin-dev
```

`librizin-dev` provides the C headers and pkg-config files needed to compile plugins.

#### 3. Install build tools

```bash
sudo apt install meson ninja-build gcc pkg-config
```

| Tool | Purpose |
|------|---------|
| `gcc` | C11 compiler |
| `meson` | Build system generator |
| `ninja-build` | Fast build executor (Meson backend) |
| `pkg-config` | Locates Rizin headers and libraries |

#### 4. Verify prerequisites

```bash
rizin -v          # Rizin version (>= 0.8.0 required)
meson --version   # Meson version
ninja --version   # Ninja version
pkg-config --modversion rz_core   # Rizin pkg-config is working
```

### Windows

#### 1. Install Rizin

Download and install the latest Rizin release for Windows from:
<https://github.com/rizinorg/rizin/releases>

Use the `.msi` or `.zip` package. Make sure Rizin's `bin` directory is in your `PATH` so that `pkg-config` can find the Rizin installation.

#### 2. Install a C compiler

You need one of the following:

- **MSVC** -- Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) with the "Desktop development with C++" workload. This provides `cl.exe` and the Developer Command Prompt.
- **MinGW-w64** -- Install from <https://www.mingw-w64.org/> or via MSYS2 (`pacman -S mingw-w64-x86_64-gcc`).

#### 3. Install Meson and Ninja

Download and install Meson from:
<https://mesonbuild.com>

Meson's Windows installer includes Ninja. Alternatively, install via pip:

```powershell
pip install meson ninja
```

Or via MSYS2:

```bash
pacman -S mingw-w64-x86_64-meson mingw-w64-x86_64-ninja
```

#### 4. Install pkg-config (if not already present)

Rizin's Windows package typically includes `pkg-config`. If not, install it via MSYS2:

```bash
pacman -S mingw-w64-x86_64-pkg-config
```

Or use `pkgconf` as a drop-in replacement.

#### 5. Verify prerequisites

Open a Developer Command Prompt (MSVC) or MSYS2/MinGW terminal and run:

```powershell
rizin -v
meson --version
ninja --version
pkg-config --modversion rz_core
```

---

## Building

### Linux

```bash
git clone https://github.com/<your-org>/rz-nd100
cd rz-nd100
meson setup build
ninja -C build
```

### Windows (Developer Command Prompt or MSYS2 terminal)

```powershell
git clone https://github.com/<your-org>/rz-nd100
cd rz-nd100
meson setup build
ninja -C build
```

> Replace `<your-org>` with the actual GitHub organization or username.

### Build options

The project uses C11 and warning level 2 by default. You can override Meson options as usual:

```bash
meson setup build -Dwarning_level=3
```

The plugin installation directory is determined automatically from Rizin's pkg-config. No manual path configuration is needed.

---

## Build output

After a successful build, the `build/` directory contains:

```
build/
  asm_nd100.so          # Disassembler plugin
  analysis_nd100.so     # Analysis plugin
  bin_aout16.so         # a.out16 binary loader
  bin_bpun.so           # BPUN binary loader
```

On Windows the extensions will be `.dll` instead of `.so`.

---

## Installing

See [INSTALL.md](INSTALL.md) for how to install the built plugins into Rizin and verify the installation.

Quick summary:

```bash
# Linux
sudo ninja -C build install

# Windows
ninja -C build install
```

---

## Cleaning

To remove all build artifacts:

```bash
rm -rf build
```

To reconfigure from scratch:

```bash
meson setup build --wipe
```

---

## Troubleshooting

### `rz_core` dependency not found

Meson cannot find Rizin via pkg-config. Ensure `librizin-dev` (Linux) or Rizin (Windows) is installed and that `pkg-config` can locate it:

```bash
pkg-config --modversion rz_core
```

If Rizin is installed in a non-standard location, set `PKG_CONFIG_PATH`:

```bash
export PKG_CONFIG_PATH=/path/to/rizin/lib/pkgconfig:$PKG_CONFIG_PATH
```

### Wrong Rizin version

This plugin requires Rizin >= 0.8.0 (which merged `rz_asm` into `rz_arch`). Check your version with `rizin -v` and upgrade if needed.
