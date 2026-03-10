# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
meson setup build          # Configure (first time or after meson.build changes)
ninja -C build             # Build all five plugins
sudo ninja -C build install  # Install into Rizin's plugin directory (Linux)
meson setup build --wipe   # Reconfigure from scratch
```

Verify plugins load correctly:
```bash
rz-asm -L | grep nd100
rizin -qc 'iL' /dev/null | grep -E 'bpun|aout16'
```

There are no automated tests or linting configurations in this project.

## Architecture

This is a Rizin plugin suite for the Norsk Data ND-100/ND-110 16-bit minicomputer. It builds five shared library plugins (.so/.dll) from `src/`:

**Shared decoder layer** (linked into asm and analysis plugins):
- `nd100_disasm.c/h` -- core instruction decoder, adapted from the nd100x emulator. Called via `nd100_disasm(word, buf, bufsz, cpu_mode)`.
- `moncalls.c/h` -- SINTRAN III MON call lookup table. `mon_lookup(num)` returns name/description.
- `iodevs.c/h` -- IOX device register lookup table. `iox_lookup(addr)` returns device/register/direction.

**Plugin files** (each produces one .so/.dll):
- `rz_asm_nd100.c` -- disassembler AND assembler plugin (`RzAsmPlugin`). Disassembles via `nd100_disasm()` with MON/IOX annotations. Assembles the full ND-100/ND-110 instruction set including all addressing modes, register operations, bit operations, shifts, and nd100-as compatible syntax (trailing comma: `LDA -4,B`).
- `rz_analysis_nd100.c` -- analysis plugin (`RzAnalysisPlugin`). Full opcode classification with op families (CPU/FPU/IO/PRIV), ESIL emulation strings, stack tracking, condition types, address_bits callback, and function prologue detection (COPY SL DA, ENTR, INIT).
- `rz_parse_nd100.c` -- pseudo-code plugin (`RzParsePlugin`). Translates ND-100 assembly to C-like pseudo-code for `pdc` output. Handles loads, stores, arithmetic, branches, MON calls, IOX, shifts, SKP, register ops, and bit operations.
- `rz_bin_bpun.c` -- BPUN bootstrap loader (`RzBinPlugin`). Parses ASCII preamble + binary sections, big-endian.
- `rz_bin_aout16.c` -- a.out16 loader (`RzBinPlugin`). Parses header/segments/symbols/relocations, little-endian. Includes `imports`, `relocs`, `binsym`, `fields`, and `header` callbacks.

Each plugin exports a `RzLibStruct rizin_plugin` with type, data pointer, and `RZ_VERSION`. The install directory is auto-detected from Rizin's pkg-config `plugindir` variable.

## Coding Conventions

- C11 standard, warning level 2. No Unicode anywhere in source (comments, strings, identifiers) -- the toolchain is from the late 80s era.
- Opcodes are compared as hex in C code (e.g., `0xD600`) but ND-100 operands are displayed in octal in disassembly output.
- All string formatting uses `snprintf` with explicit buffer sizes.
- No external dependencies beyond Rizin (`rz_core` via pkg-config).

## Key Bit Patterns

The analysis plugin classifies instructions by their top bits:
- `0xD600` range -- MON (monitor/syscall), type `RZ_ANALYSIS_OP_TYPE_SWI`
- `0xCC00` range -- EXIT/return, type `RZ_ANALYSIS_OP_TYPE_RET`
- `0xA800` range -- JMP (unconditional), type `RZ_ANALYSIS_OP_TYPE_JMP`
- `0xA000-0xA700` -- conditional branches (JAP, JAN, JAZ, JAF), type `RZ_ANALYSIS_OP_TYPE_CJMP`
- `0xB000` range -- JPL (call), type `RZ_ANALYSIS_OP_TYPE_CALL`
- `0xF800` range -- skip instructions (SKP, BSKP), type `RZ_ANALYSIS_OP_TYPE_CJMP` with jump=PC+4, fail=PC+2
