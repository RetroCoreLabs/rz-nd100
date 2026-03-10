# rz-nd100

[![License: LGPL-3.0](https://img.shields.io/badge/License-LGPL--3.0-blue.svg)](LICENSE)
[![Rizin](https://img.shields.io/badge/Rizin-%3E%3D%200.8.0-orange.svg)](https://rizin.re/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)](#)
[![C Standard](https://img.shields.io/badge/C-C11-blue.svg)](#)

**Reverse-engineer Norsk Data ND-100/ND-110 minicomputer binaries using modern tools.**

A plugin suite for [Rizin](https://rizin.re/) and [Cutter](https://cutter.re/) that brings full disassembly, assembly, ESIL emulation, pseudo-code output, control flow analysis, and binary format support for the ND-100 architecture -- with automatic SINTRAN III system call and I/O device annotations.

---

## Table of Contents

- [What It Looks Like](#what-it-looks-like)
- [Plugins](#plugins)
- [Features](#features)
- [Quick Start](#quick-start)
- [Using with Cutter (GUI)](#using-with-cutter-gui)
- [Documentation](#documentation)
- [About the ND-100](#about-the-nd-100)
- [Contributing](#contributing)
- [Releases](#releases)
- [Acknowledgements](#acknowledgements)
- [License](#license)

---

## What It Looks Like

**Disassembly with I/O device annotations** -- IOX instructions are automatically decoded to show the device name, register, and direction:

```
            ;-- entry0:
            ;-- section.code:
            0x00000000      STZ   I ,B -146
            0x00000002      STZ   I ,B ,X 122
            0x00000004      IOX   1562 ; FLP1 Read Status 1 (Read)
        +-- 0x00000006      JAN   47
        |   0x00000008      SAA   60
        |   0x0000000a      IOX   1563 ; FLP1 Load Control (Write)
        |   0x0000000c      LDA   62
        |   0x0000000e      IOX   1565 ; FLP1 Load Pointer High (Write)
```

**Round-trip assembler** -- assemble ND-100 instructions and get them back:

```
$ rz-asm -a nd100 'LDA ,B -4'
fc49
$ rz-asm -a nd100 -d fc49
LDA ,B -4
```

**Pseudo-code output** -- C-like translation of ND-100 assembly:

```
[0x00000000]> e asm.pseudo=true
[0x00000000]> pd 4
            0x00000000      a = 5
            0x00000002      a = *(b + 10)
            0x00000004      *(b + 5) = a
            0x00000006      if (a > 0) goto 0x14
```

**Function analysis with loop detection** -- branch arrows, cross-references, and skip instruction flow are all tracked:

```
  ; CALL XREF from aav.0x00000300 @ +0x36
  fcn.0000037c();
      0x0000037c      SAA   40
      0x0000037e      IOX   1563 ; FLP1 Load Control (Write)
      0x00000380      LDA   -75
      0x00000382      RADD  CLD SA DX
      0x00000384      ADD   16
      0x00000386      RADD  CLD SA DT
      ; CODE XREF from fcn.0000037c @ 0x390
  +-> 0x00000388      IOX   1560 ; FLP1 Read Data (Read)
  |   0x0000038a      STA   ,X 0
  |   0x0000038c      AAX   1
  +-- 0x0000038e      SKP   IF DX EQL ST
  |+- 0x00000390      JMP   -4
  |+> 0x00000392      STZ   -101
  |   0x00000394      SAA   40
  |   0x00000396      IOX   1563 ; FLP1 Load Control (Write)
      0x00000398      EXIT
```

**SINTRAN III system calls** -- MON instructions are annotated with the call name and description:

```
$ rz-asm -a nd100 -e -d a80ad600cc62
JMP 12
MON 0 ; LEAVE - ExitFromProgram
EXIT
```

---

## Plugins

The build produces five plugins that integrate seamlessly with Rizin and Cutter:

| Plugin | Type | Description |
|--------|------|-------------|
| **asm_nd100** | Assembler | Full ND-100/ND-110 disassembly and assembly with inline MON and IOX annotations |
| **analysis_nd100** | Analysis | Control flow, ESIL emulation, op classification, frame tracking, function prologue detection |
| **parse_nd100** | Parser | C-like pseudo-code output for `pdc` / `asm.pseudo=true` |
| **bin_aout16** | Binary loader | ND-100 a.out16 executables and object files with symbols, imports, relocations, header display |
| **bin_bpun** | Binary loader | BPUN and FloMon bootstrap punch files with auto-detection |

---

## Features

### Disassembly

- Complete ND-100 instruction set: memory reference, register ops, I/O, skip, branch, bit operations, shifts, privileged instructions
- ND-110 extended instructions via `asm.cpu=nd110` (VERSN, WGLOB, LASB, RGLOB, INSPL, etc.)
- Both big-endian (BPUN) and little-endian (a.out16) byte orders

### Assembler

- Full round-trip assembly of the entire ND-100/ND-110 instruction set
- All 8 addressing modes: direct, B-relative, indirect, indirect B, X-indexed, X+B, indirect X, indirect B+X
- Supports both Rizin disassembly syntax (`LDA ,B -4`) and nd100-as assembler syntax (`LDA -4,B`)
- Register operations with all modifiers (CLD, CM1, AD1, ADC)
- Bit operations with conditions (BSET/BSKP ZRO/ONE/BCM/BAC) and status bit names
- Shift instructions with ROT/ZIN/LIN types and SHR direction
- Register aliases: RCLR, RINC, RDCR, COPY
- Physical memory instructions: LDATX, LDXTX, LDDTX, LDBTX, STATX, STZTX, STDTX
- IRW/IRR with level and register arguments
- IDENT PL10/PL11/PL12/PL13
- ND-110 delta instructions: LASB, SASB, LACB, SACB, LXSB, LXCB, SZSB, SZCB

### ESIL Emulation

- ESIL (Evaluable Strings Intermediate Language) strings for instruction stepping
- Memory reference load/store/arithmetic with all addressing modes
- Branch and skip condition evaluation
- Register operation ESIL (RADD, RADD CLD, etc.)
- Shift and argument instruction ESIL
- MON trap ESIL
- Enables `aes` (step), `aec` (continue), and `aepc` (set PC) commands

### Pseudo-Code

- C-like pseudo-code output via `pdc` or `e asm.pseudo=true`
- Translates loads to `a = *(b + offset)`, stores to `*(b + offset) = a`
- Branches to `if (a > 0) goto addr`, MON calls to `TRAP(name)`, etc.
- IOX, shifts, register ops, bit operations, and skip instructions all supported

### Annotations

- **SINTRAN III MON calls** resolved to name and description
  `MON 50 ; OPEN - OpenFile`
- **IOX device registers** decoded with device name, register, and I/O direction
  `IOX 1562 ; FLP1 Read Status 1 (Read)`

### Analysis

- Function discovery and basic block detection
- **Op family classification**: CPU, FPU, I/O, and privileged instruction families
- **Function prologue detection** -- automatically finds C functions (`COPY SL DA`), PLANC/COBOL entries (`ENTR`), and frame initialization (`INIT`)
- Branch arrows for conditional jumps, loops, and skip instructions
- Cross-reference tracking for calls and jumps
- Condition types for all conditional instructions (EQL, GRE, LSS, etc.)
- Full ND-100 register profile: S (status), D, P, B (frame pointer), L (link), A (accumulator), T, X (index)
- Address bits callback (16-bit)

**Note:** The ND-100 has no hardware stack. The B register serves as a frame pointer in the ENTR/LEAVE calling convention. Frame-relative accesses (B-relative addressing modes) are tracked for variable detection.

### Binary Formats

- **a.out16** -- symbol tables, relocation entries, text/data/bss segments, auto-detected by magic `0407`
  - **Imports** -- undefined external symbols exposed via `ii` for dependency analysis
  - **Relocations** -- full relocation table parsing (REL_TEXT, REL_DATA, REL_BSS, REL_UNDEXT, REL_BPTR) via `ir`
  - **Header display** -- formatted header via `ih` showing magic, sizes, entry point
  - **Fields** -- structured header fields via `iH`
  - **Special symbols** -- entry point and main detection via `.binsym`
- **BPUN** -- preamble parsing, multi-section bootstrap loading, FloMon variant support

---

## Quick Start

```bash
# Build and install
meson setup build
ninja -C build
sudo ninja -C build install
```

```bash
# Open a BPUN bootstrap
rizin FLOPPY-MON-2010G.BPUN

# Open an a.out16 executable (symbols loaded automatically)
rizin boot.out

# Run analysis and explore
[0x00000000]> aaa            # Full auto-analysis
[0x00000000]> afl            # List discovered functions
[0x00000000]> pdf @ entry0   # Disassemble entry point
[0x00000000]> /ad MON        # Find all SINTRAN III system calls
[0x00000000]> /ad IOX        # Find all I/O operations
[0x00000000]> VV @ entry0    # Visual control flow graph
```

```bash
# Assemble and disassemble from the command line
rz-asm -a nd100 'LDA ,B -4'          # Assemble -> fc49
rz-asm -a nd100 'LDA -4,B'           # nd100-as syntax also works
rz-asm -a nd100 -d fc49              # Disassemble -> LDA ,B -4
rz-asm -a nd100 'BSKP ONE 10 DA'     # Bit operations
rz-asm -a nd100 'RADD CLD SA DA'     # Register ops with modifiers
```

See [BUILD.md](BUILD.md) for prerequisites and platform-specific setup.

---

## Using with Cutter (GUI)

[Cutter](https://cutter.re/) is the official GUI for Rizin. Once the rz-nd100 plugins are installed, Cutter picks them up automatically -- no extra configuration needed.

1. **Open a file** -- load a `.BPUN` or a.out16 binary. Cutter auto-detects the format via the `bin_bpun` or `bin_aout16` loader and sets the architecture to `nd100`.
2. **Analyze** -- click the Analyze button (or run `aaa`) to discover functions, branches, and cross-references.
3. **Disassembly view** -- shows ND-100 instructions with inline MON call and IOX device annotations, just like the Rizin command line.
4. **Pseudo-code view** -- shows C-like pseudo-code translation of ND-100 assembly when `asm.pseudo` is enabled.
5. **Graph view** -- displays control flow graphs with branch arrows for skip instructions, conditional jumps, and loops.
6. **Functions panel** -- lists all discovered functions. For a.out16 files with symbols, the original symbol names appear here.
7. **Cross-references** -- double-click any call or jump to follow it; use the xrefs panel to see who calls a function.

For raw binary files without a recognized header, set the architecture manually in the load options dialog:
- Architecture: **nd100**
- Bits: **16**
- CPU: **nd100** (or **nd110** for extended instructions)

See [INSTALL.md](INSTALL.md) for how to install Cutter on Linux and Windows.

---

## Documentation

| Document | Description |
|----------|-------------|
| [BUILD.md](./BUILD.md) | Build prerequisites and compilation for Linux and Windows |
| [INSTALL.md](./INSTALL.md) | Plugin installation into Rizin, Cutter setup, and verification |
| [GETTING-STARTED.md](./GETTING-STARTED.md) | Practical walkthrough: opening files, analysis, assembler, ESIL, pseudo-code |
| [ROADMAP.md](./ROADMAP.md) | Feature roadmap and implementation status |

---

## About the ND-100

The [Norsk Data](https://en.wikipedia.org/wiki/Norsk_Data) ND-100 was a 16-bit minicomputer produced in Oslo, Norway from 1973. Running the SINTRAN III operating system, it was widely used in universities, research labs, and government institutions across Scandinavia and beyond. The ND-110 was an enhanced version with additional instructions and improved performance.

This plugin suite makes it possible to analyze surviving firmware, bootstraps, and executables from these machines using modern reverse-engineering tools.

---

## Contributing

Contributions are welcome. If you find a bug, have a feature request, or want to add support for additional ND-100 file formats or instruction variants:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make your changes and test them
4. Submit a pull request

Please keep the code style consistent with the existing codebase (C11, no Unicode in source files).

---

## Releases

Pre-built plugins for Linux and Windows are available on the [Releases](https://github.com/HackerCorpLabs/rz-nd100/releases) page.

### Creating a new release

1. Update the version in `meson.build`:
   ```
   project('rz-nd100', 'c',
       version: '1.1.0',
   ```

2. Update the version string in the plugin structs in `src/rz_asm_nd100.c`, `src/rz_analysis_nd100.c`, `src/rz_parse_nd100.c`, `src/rz_bin_bpun.c`, and `src/rz_bin_aout16.c`.

3. Commit the version bump:
   ```bash
   git add -A
   git commit -m "Bump version to 1.1.0"
   ```

4. Tag and push:
   ```bash
   git tag v1.1.0
   git push && git push --tags
   ```

The CI workflow builds both Linux and Windows plugins, runs the assembler round-trip tests, and then creates a GitHub release with two archives attached:

- `rz-nd100-linux-x86_64.tar.gz` -- five `.so` plugin files
- `rz-nd100-windows-x86_64.zip` -- five `.dll` plugin files

Release notes are auto-generated from the commit history since the previous tag.

---

## Acknowledgements

- The instruction decoder was adapted from [nd100x](https://github.com/HackerCorpLabs/nd100x), an ND-100 emulator
- Assembler syntax informed by [nd100-as](https://github.com/HackerCorpLabs/nd100-as), an ND-100 cross-assembler
- Built on the [Rizin](https://rizin.re/) reverse-engineering framework
- MON call and IOX device tables derived from original Norsk Data documentation

---

## License

This project is licensed under [LGPL-3.0-only](LICENSE).

The decoder engine is adapted from the nd100x emulator, licensed under GPL-2.0-or-later.
