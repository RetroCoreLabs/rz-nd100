# rz-nd100

[![License: LGPL-3.0](https://img.shields.io/badge/License-LGPL--3.0-blue.svg)](LICENSE)
[![Rizin](https://img.shields.io/badge/Rizin-%3E%3D%200.8.0-orange.svg)](https://rizin.re/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey.svg)](#)
[![C Standard](https://img.shields.io/badge/C-C11-blue.svg)](#)

**Reverse-engineer Norsk Data ND-100/ND-110 minicomputer binaries using modern tools.**

A plugin suite for [Rizin](https://rizin.re/) and [Cutter](https://cutter.re/) that brings full disassembly, control flow analysis, and binary format support for the ND-100 architecture -- with automatic SINTRAN III system call and I/O device annotations.

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

The build produces four plugins that integrate seamlessly with Rizin and Cutter:

| Plugin | Type | Description |
|--------|------|-------------|
| **asm_nd100** | Disassembler | Full ND-100/ND-110 instruction decoding with inline MON and IOX annotations |
| **analysis_nd100** | Analysis | Control flow, branch/call/skip detection, cross-references, 8-register profile |
| **bin_aout16** | Binary loader | ND-100 a.out16 executables and object files with symbols, imports, relocations, and segments |
| **bin_bpun** | Binary loader | BPUN and FloMon bootstrap punch files with auto-detection |

---

## Features

### Disassembly
- Complete ND-100 instruction set: memory reference, register ops, I/O, skip, branch
- ND-110 extended instructions via `asm.cpu=nd110` (VERSN, WGLOB, LASB, etc.)
- Both big-endian (BPUN) and little-endian (a.out16) byte orders

### Annotations
- **SINTRAN III MON calls** resolved to name and description
  `MON 50 ; OPEN - OpenFile`
- **IOX device registers** decoded with device name, register, and I/O direction
  `IOX 1562 ; FLP1 Read Status 1 (Read)`

### Analysis
- Function discovery and basic block detection
- **Function prologue detection** -- automatically finds C functions (`COPY SL DA`), PLANC/COBOL entries (`ENTR`), and stack initialization (`INIT`)
- Branch arrows for conditional jumps, loops, and skip instructions
- Cross-reference tracking for calls and jumps
- Full ND-100 register profile: A, T, X, B, L, D, S, P

### Binary Formats
- **a.out16** -- symbol tables, relocation entries, text/data/bss segments, auto-detected by magic `0407`
  - **Imports** -- undefined external symbols exposed via `ii` for dependency analysis
  - **Relocations** -- full relocation table parsing (REL_TEXT, REL_DATA, REL_BSS, REL_UNDEXT, REL_BPTR) via `ir`
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

See [BUILD.md](BUILD.md) for prerequisites and platform-specific setup.

---

## Using with Cutter (GUI)

[Cutter](https://cutter.re/) is the official GUI for Rizin. Once the rz-nd100 plugins are installed, Cutter picks them up automatically -- no extra configuration needed.

1. **Open a file** -- load a `.BPUN` or a.out16 binary. Cutter auto-detects the format via the `bin_bpun` or `bin_aout16` loader and sets the architecture to `nd100`.
2. **Analyze** -- click the Analyze button (or run `aaa`) to discover functions, branches, and cross-references.
3. **Disassembly view** -- shows ND-100 instructions with inline MON call and IOX device annotations, just like the Rizin command line.
4. **Graph view** -- displays control flow graphs with branch arrows for skip instructions, conditional jumps, and loops.
5. **Functions panel** -- lists all discovered functions. For a.out16 files with symbols, the original symbol names appear here.
6. **Cross-references** -- double-click any call or jump to follow it; use the xrefs panel to see who calls a function.

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
| [GETTING-STARTED.md](./GETTING-STARTED.md) | Practical walkthrough: opening files, analysis, searching, visual modes |

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

## Acknowledgements

- The instruction decoder was adapted from [nd100x](https://github.com/HackerCorpLabs/nd100x), an ND-100 emulator
- Built on the [Rizin](https://rizin.re/) reverse-engineering framework
- MON call and IOX device tables derived from original Norsk Data documentation

---

## License

This project is licensed under [LGPL-3.0-only](LICENSE).

The decoder engine is adapted from the nd100x emulator, licensed under GPL-2.0-or-later.
