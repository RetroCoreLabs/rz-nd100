# Installing the rz-nd100 Plugins

This guide covers installing the rz-nd100 Rizin plugins on Linux and Windows from pre-built release archives.

If you want to build from source instead, see [Building from Source](#building-from-source) at the bottom of this document.

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

---

## Step 1: Install Rizin

You must install Rizin before installing the plugins.

### Linux (Ubuntu/Debian)

Install Rizin from the RizinOrg OBS repository (Ubuntu 22.04):

```bash
echo 'deb http://download.opensuse.org/repositories/home:/RizinOrg/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/home:RizinOrg.list
curl -fsSL https://download.opensuse.org/repositories/home:RizinOrg/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_RizinOrg.gpg > /dev/null
sudo apt update
sudo apt install rizin
```

Verify:

```bash
rizin -v
```

Rizin is installed to `/usr/bin/` and is immediately available from any terminal.

### Windows

Download and install the latest Rizin release from:
<https://github.com/rizinorg/rizin/releases>

The `.msi` installer is recommended. It typically installs Rizin to:

```
%LOCALAPPDATA%\Programs\rizin
```

For example: `C:\Users\YourName\AppData\Local\Programs\rizin`

The installer does **not** add Rizin to your `PATH` automatically, so you will not be able to run `rizin` or `rz-asm` from a command prompt without either adding it to your PATH or using the full path.

#### Finding the Rizin install location

If you installed Rizin but cannot find it, search for `rizin.exe`:

```powershell
where /R "%LOCALAPPDATA%" rizin.exe
```

Or search more broadly:

```powershell
where /R "C:\Users\%USERNAME%" rizin.exe
```

#### Adding Rizin to your PATH (permanently -- recommended)

To make `rizin`, `rz-asm`, and other Rizin tools available in all terminal sessions:

1. Press **Win + R**, type `sysdm.cpl`, press Enter.
2. Go to the **Advanced** tab and click **Environment Variables**.
3. Under **User variables**, select **Path** and click **Edit**.
4. Click **New** and add the Rizin install directory (e.g. `C:\Users\YourName\AppData\Local\Programs\rizin`).
5. Click **OK** on all dialogs.
6. Open a **new** command prompt and verify:

```powershell
rizin -v
```

Alternatively, from PowerShell (run as Administrator):

```powershell
[Environment]::SetEnvironmentVariable("Path", "$env:LOCALAPPDATA\Programs\rizin;" + [Environment]::GetEnvironmentVariable("Path", "User"), "User")
```

Open a **new** terminal window after changing the PATH for it to take effect.

#### Adding Rizin to your PATH (current session only)

If you just want to use Rizin in the current terminal without a permanent change:

```powershell
# Command Prompt
set PATH=%LOCALAPPDATA%\Programs\rizin;%PATH%

# PowerShell
$env:PATH = "$env:LOCALAPPDATA\Programs\rizin;$env:PATH"
```

#### Running Rizin without modifying PATH

You can always run Rizin directly using its full path:

```powershell
# Command Prompt
"%LOCALAPPDATA%\Programs\rizin\rizin.exe" -v
"%LOCALAPPDATA%\Programs\rizin\rz-asm.exe" -L | findstr nd100

# PowerShell
& "$env:LOCALAPPDATA\Programs\rizin\rizin.exe" -v
& "$env:LOCALAPPDATA\Programs\rizin\rz-asm.exe" -L | Select-String nd100
```

---

## Step 2: Install the Plugins

Pre-built plugin archives for Linux and Windows are available on the [Releases](https://github.com/HackerCorpLabs/rz-nd100/releases) page.

### Linux

1. Download `rz-nd100-linux-x86_64.tar.gz` from the latest release.

2. Find your Rizin plugin directory:

   ```bash
   PLUGDIR=$(rizin -H RZ_USER_PLUGINS)
   echo "$PLUGDIR"
   ```

   This is typically `~/.local/lib/rizin/plugins` or similar. If you prefer a system-wide install, use the system plugin directory instead:

   ```bash
   PLUGDIR=$(rizin -H RZ_LIB_PLUGINS)
   echo "$PLUGDIR"
   ```

3. Create the plugin directory if it does not exist and extract the plugins:

   ```bash
   mkdir -p "$PLUGDIR"
   tar xzf rz-nd100-linux-x86_64.tar.gz -C "$PLUGDIR"
   ```

   For the system-wide directory, prefix with `sudo`:

   ```bash
   sudo mkdir -p "$PLUGDIR"
   sudo tar xzf rz-nd100-linux-x86_64.tar.gz -C "$PLUGDIR"
   ```

4. Verify the files are in place:

   ```bash
   ls -la "$PLUGDIR"/*.so
   ```

   You should see `asm_nd100.so`, `analysis_nd100.so`, `parse_nd100.so`, `bin_aout16.so`, and `bin_bpun.so`.

### Windows

1. Download `rz-nd100-windows-x86_64.zip` from the latest release.

2. Find your Rizin plugin directory. Open a command prompt and run:

   ```powershell
   rizin -H RZ_USER_PLUGINS
   ```

   This is typically `%APPDATA%\rizin\plugins` or similar.

3. Create the plugin directory if it does not exist and extract the `.dll` files into it.

   **Using PowerShell:**

   ```powershell
   $plugdir = (rizin -H RZ_USER_PLUGINS).Trim()
   New-Item -ItemType Directory -Force -Path $plugdir
   Expand-Archive -Path rz-nd100-windows-x86_64.zip -DestinationPath $plugdir -Force
   ```

   **Manually:** open the directory shown by `rizin -H RZ_USER_PLUGINS` in Explorer (create it if it does not exist) and copy all five `.dll` files from the zip into it.

4. Verify the files are in place:

   ```powershell
   dir $plugdir\*.dll
   ```

   You should see `asm_nd100.dll`, `analysis_nd100.dll`, `parse_nd100.dll`, `bin_aout16.dll`, and `bin_bpun.dll`.

---

## Step 3: Install Cutter (Optional GUI)

[Cutter](https://cutter.re/) is the official GUI for Rizin. Once the rz-nd100 plugins are installed, Cutter picks them up automatically -- no extra configuration needed.

### Linux

Install Cutter from the same RizinOrg OBS repository:

```bash
sudo apt install cutter-re
```

### Windows

Download the Cutter installer from:
<https://github.com/rizinorg/cutter/releases>

---

## Step 4: Verify the Installation

After installing Rizin and the plugins, verify that everything loads correctly.

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

On Windows (Command Prompt), use double quotes:

```powershell
rz-asm -a nd100 "LDA ,B -4"
rz-asm -a nd100 -d fc49
```

### Analysis plugin (analysis_nd100)

```bash
rizin -qc "e asm.arch=nd100; aai" /dev/null 2>&1 | head -1
```

If no errors appear, the analysis plugin is loaded correctly.

On Windows, use `NUL` instead of `/dev/null`:

```powershell
rizin -qc "e asm.arch=nd100; aai" NUL
```

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

On Windows:

```powershell
rizin -qc "iL" NUL | findstr "aout16 bpun"
```

### Using Cutter (GUI)

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

Remove the five plugin files from the plugin directory:

**Linux:**

```bash
PLUGDIR=$(rizin -H RZ_USER_PLUGINS)
rm -f "$PLUGDIR"/asm_nd100.so "$PLUGDIR"/analysis_nd100.so "$PLUGDIR"/parse_nd100.so "$PLUGDIR"/bin_aout16.so "$PLUGDIR"/bin_bpun.so
```

**Windows (PowerShell):**

```powershell
$plugdir = (rizin -H RZ_USER_PLUGINS).Trim()
Remove-Item "$plugdir\asm_nd100.dll", "$plugdir\analysis_nd100.dll", "$plugdir\parse_nd100.dll", "$plugdir\bin_aout16.dll", "$plugdir\bin_bpun.dll"
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

If you prefer to compile the plugins yourself rather than using the pre-built release, you will need a C compiler, Meson, Ninja, and the Rizin development headers. See [BUILD.md](BUILD.md) for full details.

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
