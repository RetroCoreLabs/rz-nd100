# Installing the rz-nd100 Plugins

This guide covers installing the rz-nd100 Rizin plugins on Linux and Windows from pre-built release archives.

## Table of Contents

- [Plugins Overview](#plugins-overview)
- [Windows](#windows)
  - [Install Rizin](#install-rizin)
  - [Add Rizin to PATH](#add-rizin-to-path)
  - [Install the Plugins](#install-the-plugins)
  - [Install Cutter (Optional GUI)](#install-cutter-optional-gui)
  - [Verify the Installation](#verify-the-installation)
- [Linux](#linux)
  - [Install Rizin](#install-rizin-1)
  - [Install the Plugins](#install-the-plugins-1)
  - [Install Cutter (Optional GUI)](#install-cutter-optional-gui-1)
  - [Verify the Installation](#verify-the-installation-1)
- [Using Cutter](#using-cutter)
- [Uninstalling](#uninstalling)
- [Building from Source](#building-from-source)

---

## Plugins Overview

The rz-nd100 project provides five plugins:

| Plugin | File (Linux / Windows) | Type | Purpose |
|--------|------------------------|------|---------|
| **asm_nd100** | `asm_nd100.so` / `asm_nd100.dll` | Assembler | Disassembles and assembles ND-100/ND-110 instructions, annotates MON calls and IOX registers |
| **analysis_nd100** | `analysis_nd100.so` / `analysis_nd100.dll` | Analysis | Control flow analysis, ESIL emulation, op classification, register definitions |
| **parse_nd100** | `parse_nd100.so` / `parse_nd100.dll` | Parser | C-like pseudo-code output for `pdc` and `asm.pseudo` |
| **bin_aout16** | `bin_aout16.so` / `bin_aout16.dll` | Binary loader | Loads ND-100 a.out16 executable and object files (symbols, relocations, segments, header) |
| **bin_bpun** | `bin_bpun.so` / `bin_bpun.dll` | Binary loader | Loads BPUN and FloMon bootstrap files |

Pre-built plugin archives for both platforms are available on the [Releases](https://github.com/HackerCorpLabs/rz-nd100/releases) page.

---

## Windows

### Install Rizin

Download and install Rizin (version 0.8.0 or later) from:
<https://github.com/rizinorg/rizin/releases>

The pre-built Windows plugins are built against Rizin 0.8.2. The `.msi` installer is recommended. It typically installs Rizin to:

```
%LOCALAPPDATA%\Programs\rizin
```

For example: `C:\Users\YourName\AppData\Local\Programs\rizin`

The executables (`rizin.exe`, `rz-asm.exe`, etc.) are in the `bin` subdirectory:

```
%LOCALAPPDATA%\Programs\rizin\bin
```

### Add Rizin to PATH

The Rizin installer does **not** add itself to your `PATH` automatically. Without this step, you cannot run `rizin` or `rz-asm` from a command prompt.

#### Finding the install location

If you already installed Rizin but cannot find it:

```powershell
where /R "%LOCALAPPDATA%" rizin.exe
```

Or search more broadly:

```powershell
where /R "C:\Users\%USERNAME%" rizin.exe
```

#### Permanently (recommended)

1. Press **Win + R**, type `sysdm.cpl`, press Enter.
2. Go to the **Advanced** tab and click **Environment Variables**.
3. Under **User variables**, select **Path** and click **Edit**.
4. Click **New** and add the Rizin `bin` directory (e.g. `C:\Users\YourName\AppData\Local\Programs\rizin\bin`).
5. Click **OK** on all dialogs.
6. Open a **new** command prompt and verify:

```powershell
rizin -v
```

Alternatively, from PowerShell (run as Administrator):

```powershell
[Environment]::SetEnvironmentVariable("Path", "$env:LOCALAPPDATA\Programs\rizin\bin;" + [Environment]::GetEnvironmentVariable("Path", "User"), "User")
```

Open a **new** terminal window after changing the PATH for it to take effect.

#### Current session only

```powershell
# Command Prompt
set PATH=%LOCALAPPDATA%\Programs\rizin\bin;%PATH%

# PowerShell
$env:PATH = "$env:LOCALAPPDATA\Programs\rizin\bin;$env:PATH"
```

#### Without modifying PATH

You can always run Rizin using its full path:

```powershell
# Command Prompt
"%LOCALAPPDATA%\Programs\rizin\bin\rizin.exe" -v

# PowerShell
& "$env:LOCALAPPDATA\Programs\rizin\bin\rizin.exe" -v
```

### Install the Plugins

1. Download `rz-nd100-windows.zip` from the [latest release](https://github.com/HackerCorpLabs/rz-nd100/releases).

2. Find your Rizin plugin directory:

   ```powershell
   rizin -H RZ_USER_PLUGINS
   ```

   This is typically `%USERPROFILE%\.local\lib\rizin\plugins` (e.g. `C:\Users\YourName\.local\lib\rizin\plugins`).

3. Create the plugin directory if it does not exist and extract the `.dll` files into it.

   **Using PowerShell:**

   ```powershell
   $plugdir = (rizin -H RZ_USER_PLUGINS).Trim()
   New-Item -ItemType Directory -Force -Path $plugdir
   Expand-Archive -Path "$HOME\Downloads\rz-nd100-windows.zip" -DestinationPath $plugdir -Force
   ```

   Adjust the path to the zip file if you saved it somewhere other than your Downloads folder.

   **Manually:** open the directory shown by `rizin -H RZ_USER_PLUGINS` in Explorer (create it if it does not exist) and copy all five `.dll` files from the zip into it.

4. Verify the files are in place:

   ```powershell
   dir $plugdir\*.dll
   ```

   You should see `asm_nd100.dll`, `analysis_nd100.dll`, `parse_nd100.dll`, `bin_aout16.dll`, and `bin_bpun.dll`.

### Install Cutter (Optional GUI)

Download the Cutter installer from:
<https://github.com/rizinorg/cutter/releases>

Once the rz-nd100 plugins are installed into Rizin's plugin directory, Cutter picks them up automatically -- no extra configuration needed.

### Verify the Installation

**Assembler plugin:**

```powershell
rz-asm -L | findstr nd100
```

Expected output:

```
adAe_ 16         nd100       LGPL3   Norsk Data ND-100/ND-110 disassembler and assembler (by Ronny Hansen) v1.0.3
```

The `A` flag confirms assembler support is available.

Quick assembler test:

```powershell
rz-asm -a nd100 "LDA ,B -4"
rz-asm -a nd100 -d fc49
```

Expected: `fc49` and `LDA ,B -4`.

**Analysis and parser plugins:**

```powershell
rizin -qc "e asm.arch=nd100; aai" NUL
```

If no errors appear, the analysis plugin is loaded correctly.

**Binary loader plugins:**

```powershell
rizin -qc "iL" NUL | findstr "aout16 bpun"
```

Expected output:

```
bin  aout16      Norsk Data ND-100 a.out16 format (LGPL3) 1.0.3 Ronny Hansen
bin  bpun        Norsk Data BPUN bootstrap format (LGPL3) 1.0.3 Ronny Hansen
```

---

## Linux

### Install Rizin

Install Rizin (version 0.8.0 or later) from the RizinOrg OBS repository (Ubuntu 22.04). The pre-built Linux plugins are built against Rizin 0.8.0:

```bash
echo 'deb http://download.opensuse.org/repositories/home:/RizinOrg/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/home:RizinOrg.list
curl -fsSL https://download.opensuse.org/repositories/home:RizinOrg/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_RizinOrg.gpg > /dev/null
sudo apt update
sudo apt install rizin
```

Rizin is installed to `/usr/bin/` and is immediately available from any terminal.

Verify:

```bash
rizin -v
```

### Install the Plugins

1. Download `rz-nd100-linux.tar.gz` from the [latest release](https://github.com/HackerCorpLabs/rz-nd100/releases).

2. Find your Rizin plugin directory:

   ```bash
   PLUGDIR=$(rizin -H RZ_USER_PLUGINS)
   echo "$PLUGDIR"
   ```

   This is typically `~/.local/lib/rizin/plugins` or similar. For a system-wide install, use the system plugin directory instead:

   ```bash
   PLUGDIR=$(rizin -H RZ_LIB_PLUGINS)
   echo "$PLUGDIR"
   ```

3. Create the plugin directory if it does not exist and extract the plugins:

   ```bash
   mkdir -p "$PLUGDIR"
   tar xzf rz-nd100-linux.tar.gz -C "$PLUGDIR"
   ```

   For the system-wide directory, prefix with `sudo`:

   ```bash
   sudo mkdir -p "$PLUGDIR"
   sudo tar xzf rz-nd100-linux.tar.gz -C "$PLUGDIR"
   ```

4. Verify the files are in place:

   ```bash
   ls -la "$PLUGDIR"/*.so
   ```

   You should see `asm_nd100.so`, `analysis_nd100.so`, `parse_nd100.so`, `bin_aout16.so`, and `bin_bpun.so`.

### Install Cutter (Optional GUI)

Install Cutter from the same RizinOrg OBS repository:

```bash
sudo apt install cutter-re
```

Once the rz-nd100 plugins are installed into Rizin's plugin directory, Cutter picks them up automatically -- no extra configuration needed.

### Verify the Installation

**Assembler plugin:**

```bash
rz-asm -L | grep nd100
```

Expected output:

```
adAe_ 16         nd100       LGPL3   Norsk Data ND-100/ND-110 disassembler and assembler (by Ronny Hansen) v1.0.3
```

Quick assembler test:

```bash
rz-asm -a nd100 'LDA ,B -4'     # Should output: fc49
rz-asm -a nd100 -d fc49          # Should output: LDA ,B -4
```

**Analysis and parser plugins:**

```bash
rizin -qc "e asm.arch=nd100; aai" /dev/null 2>&1 | head -1
```

If no errors appear, the analysis plugin is loaded correctly.

**Binary loader plugins:**

```bash
rizin -qc 'iL' /dev/null | grep -E "aout16|bpun"
```

Expected output:

```
bin  aout16      Norsk Data ND-100 a.out16 format (LGPL3) 1.0.3 Ronny Hansen
bin  bpun        Norsk Data BPUN bootstrap format (LGPL3) 1.0.3 Ronny Hansen
```

---

## Using Cutter

[Cutter](https://cutter.re/) is the official GUI for Rizin. These steps apply to both Windows and Linux.

1. Open Cutter and load an ND-100 binary file (a.out16 or BPUN format).
2. Cutter should auto-detect the format via the `bin_aout16` or `bin_bpun` loader.
3. In the analysis options, select **nd100** as the architecture.
4. The disassembly view should display ND-100 instructions with MON call and IOX annotations.

For raw binary files without a recognized header, set the architecture manually in the load options dialog:
- Architecture: **nd100**
- Bits: **16**
- CPU: **nd100** (or **nd110** for extended instructions)

---

## Uninstalling

### Plugins installed from release

Remove the five plugin files from the plugin directory.

**Windows (PowerShell):**

```powershell
$plugdir = (rizin -H RZ_USER_PLUGINS).Trim()
Remove-Item "$plugdir\asm_nd100.dll", "$plugdir\analysis_nd100.dll", "$plugdir\parse_nd100.dll", "$plugdir\bin_aout16.dll", "$plugdir\bin_bpun.dll"
```

**Linux:**

```bash
PLUGDIR=$(rizin -H RZ_USER_PLUGINS)
rm -f "$PLUGDIR"/asm_nd100.so "$PLUGDIR"/analysis_nd100.so "$PLUGDIR"/parse_nd100.so "$PLUGDIR"/bin_aout16.so "$PLUGDIR"/bin_bpun.so
```

### Plugins installed from source

```bash
# Linux
sudo ninja -C build uninstall

# Windows
ninja -C build uninstall
```

---

## Building from Source

If you prefer to compile the plugins yourself rather than using the pre-built release, you will need a C compiler, Meson, Ninja, and the Rizin development headers. See [BUILD.md](BUILD.md) for full prerequisites and details.

### Linux

```bash
sudo apt install rizin librizin-dev meson ninja-build gcc pkg-config
git clone https://github.com/HackerCorpLabs/rz-nd100
cd rz-nd100
meson setup build
ninja -C build
sudo ninja -C build install
```

### Windows

Building on Windows requires MSYS2 with MinGW-w64 or Visual Studio Build Tools, plus Meson and Ninja. Since Rizin is not available as an MSYS2 package, it must also be built from source. See [BUILD.md](BUILD.md) for the full procedure.

The install step copies all five plugins into Rizin's plugin directory. The correct path is determined automatically via pkg-config.
