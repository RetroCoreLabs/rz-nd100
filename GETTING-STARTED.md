# Getting Started with Rizin for ND-100

A practical guide to reverse-engineering Norsk Data ND-100/ND-110 binaries
using Rizin and the rz-nd100 plugin suite.

## Prerequisites

- Rizin 0.8.0 or later installed
- rz-nd100 plugins built and installed (see `INSTALL.md`)

Verify the plugins are loaded:

```
$ rz-asm -L | grep nd100
_dA__ 16         nd100       LGPL3   Norsk Data ND-100/ND-110 disassembler

$ rizin -qc 'iL' /dev/null | grep -E 'bpun|aout16'
bin  aout16      Norsk Data ND-100 a.out16 format
bin  bpun        Norsk Data BPUN bootstrap format
```

You should see three plugins: the disassembler/analysis (`nd100`), and two
binary loaders (`bpun` and `aout16`).

## Supported File Formats

| Format | Description | Endianness | Auto-detected |
|--------|-------------|------------|---------------|
| BPUN   | Bootstrap punch files (paper tape) | Big-endian | Yes |
| a.out16 | ND-100 object files and executables | Little-endian | Yes (magic 0407) |
| Raw binary | Plain 16-bit word dumps | Either | Manual (`-b 16`) |

## Opening Files

### BPUN Files

BPUN files are auto-detected. Rizin sets big-endian mode automatically:

```
$ rizin FLOPPY-MON-2010G.BPUN
```

### a.out16 Files

a.out16 files are also auto-detected. The loader reads the header, maps
text/data/bss segments, and imports all symbols:

```
$ rizin boot.out
```

### Raw Binary Files

For raw binary dumps without a file header, specify the architecture
manually:

```
$ rizin -a nd100 -b 16 -e cfg.bigendian=true firmware.bin
```

Use `-e cfg.bigendian=true` for big-endian data (most standalone dumps)
or omit it for little-endian.

### ND-110 Mode

To enable ND-110 extended instructions (VERSN, WGLOB, LASB, etc.):

```
$ rizin -a nd100 -e asm.cpu=nd110 somefile.BPUN
```

Or inside Rizin:

```
[0x00000000]> e asm.cpu=nd110
```

## Quick Command-Line Usage with rz-asm

You can disassemble raw hex bytes without opening a full Rizin session:

```
$ rz-asm -a nd100 -e -d d600
MON 0 ; LEAVE - ExitFromProgram

$ rz-asm -a nd100 -e -d a80ad600cc62
JMP 12
MON 0 ; LEAVE - ExitFromProgram
EXIT
```

The `-e` flag selects big-endian mode (for BPUN-style bytes).
Without `-e`, bytes are read as little-endian (a.out16 style).

## Essential Rizin Commands

### Getting File Information

```
[0x00000000]> iI          # File info (arch, bits, endianness)
arch     nd100
bits     16
endian   BE
machine  Norsk Data ND-100

[0x00000000]> ie          # Entry points
     vaddr      paddr     hvaddr      haddr type
----------------------------------------------------
0x00000000 0x000001b3 ---------- ---------- program

[0x00000000]> iS          # Sections
     paddr  size      vaddr vsize align perm name
-------------------------------------------------------------
0x000001b3 0xea6 0x00000000 0xea6   0x0 -r-x code

[0x00000000]> is          # Symbols (a.out16 files)
nth      paddr      vaddr bind   type size lib name
----------------------------------------------------------------
  0 0x00000010 0x00000000 GLOBAL FUNC    2     start
  1 0x000000aa 0x0000009a GLOBAL FUNC    2     param_head
  ...

[0x00000000]> ii          # Imports (undefined externals in .o files)
nth      vaddr bind   type lib name
-------------------------------------
  1 0x00000000 GLOBAL FUNC     csav
  2 0x00000000 GLOBAL FUNC     cret
  3 0x00000000 GLOBAL FUNC     _puts

[0x00000000]> ir          # Relocations (in .o files)
     vaddr      paddr type   name
-----------------------------------
0x00000002 0x00000012 ADD_8
0x0000000c 0x0000001c ADD_16 cret
0x0000000e 0x0000001e ADD_16 _puts
```

### Disassembly

```
[0x00000000]> pd 10       # Print 10 instructions at current position
[0x00000000]> pd 20 @ 0x100  # Print 20 instructions at address 0x100
[0x00000000]> pdf          # Print disassembly of current function
[0x00000000]> pdf @ sym.start  # Print function at symbol 'start'
```

Example output from a BPUN floppy monitor:

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

Note the inline annotations on MON and IOX instructions -- these show
the device name, register name, and I/O direction automatically.

### Navigation

```
[0x00000000]> s 0x100     # Seek to address 0x100
[0x00000000]> s sym.start # Seek to symbol
[0x00000000]> s+          # Redo seek (forward in history)
[0x00000000]> s-          # Undo seek (back in history)
```

## Analysis and Control Flow

### Running Analysis

Rizin does not analyze code automatically. You must run analysis first
to discover functions, branches, and cross-references:

```
[0x00000000]> aaa         # Full auto-analysis (recommended)
```

Or for more targeted analysis:

```
[0x00000000]> aa          # Basic analysis
[0x00000000]> aac         # Analyze function calls
[0x00000000]> aar         # Analyze xrefs
```

### Viewing Functions

```
[0x00000000]> afl         # List all discovered functions
0x00000000   19 104  -> 100  entry0
0x000002fc    1 8            fcn.000002fc
0x0000037c    4 30           fcn.0000037c
0x00000492   21 170  -> 96   fcn.00000492
0x0000053c    5 22           fcn.0000053c
...

[0x00000000]> aflc        # Count functions
8
```

The columns show: address, number of basic blocks, size, and name.

### Function Disassembly with Flow Arrows

After analysis, `pdf` shows branch arrows and cross-references:

```
[0x0000037c]> pdf
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

The arrows show:
- **Branch arrows** (`+--` / `+->`) for conditional jumps (JAN, JAZ, SKP, BSKP, etc.)
- **Loop arrows** for backward jumps
- **Call xrefs** showing where a function is called from

### Skip Instruction Flow

The analysis plugin understands all ND-100 skip-type instructions.
Each skip conditionally skips the next word (2 bytes):

| Instruction | Description |
|------------|-------------|
| SKP        | Skip on register condition |
| BSKP       | Bit skip (ZRO/ONE/BCM/BAC) |
| MIN        | Memory increment, skip on zero |
| NLZ        | Skip if leading zeros match |
| DNZ        | Decrement and skip if nonzero |
| IOXT       | IOX with transfer complete skip |
| SRB        | Skip return bit |

Example showing BSKP and IOXT flow in a real I/O polling loop:

```
  +---> 0x00000022      IOX   1562 ; FLP1 Read Status 1 (Read)
  +---< 0x00000024      BSKP  ZRO 20 DA
  |+--< 0x00000026      JMP   -2
  |+--> 0x00000028      BSKP  ZRO 40 DA
  +---< 0x0000002a      JMP   17
  +---> 0x0000002c      MIN   36
```

The BSKP tests a specific bit in the A register. If the condition is
met, the next instruction is skipped; otherwise execution falls through.

### Cross-References

```
[0x00000000]> axt @ fcn.0000037c    # Who calls this function?
(nofunc) 0x336 [CALL] JPL 43

[0x00000000]> axf @ 0x0000037c      # What does this address reference?
```

### Opcode Analysis Detail

To see the full analysis of a single instruction:

```
[0x00000024]> ao 1
address: 0x24
opcode: BSKP ZRO 20 DA
mnemonic: BSKP
type: cjmp
jump: 0x00000028
fail: 0x00000026
```

The `type` field shows how the analysis plugin classified the
instruction:
- `jmp` -- unconditional jump (JMP)
- `cjmp` -- conditional jump (JAP, JAN, SKP, BSKP, MIN, etc.)
- `call` -- subroutine call (JPL)
- `ret` -- return (EXIT, LEAVE, ELEAV)
- `swi` -- software interrupt (MON)

## Searching

### Search for Disassembly Patterns

```
[0x00000000]> /ad MON             # Find all MON (monitor call) instructions
0x00000d24   # 2: MON 2 ; OUTBT - OutByte
0x00000d26   # 2: MON 65 ; QERMS - ErrorMessage
0x00003060   # 2: MON 50 ; OPEN - OpenFile
0x00003092   # 2: MON 70 ; COMMND - CallCommand
0x0000b2b4   # 2: MON 0 ; LEAVE - ExitFromProgram

[0x00000000]> /ad IOX             # Find all IOX (I/O) instructions
0x00000004   # 2: IOX 1562 ; FLP1 Read Status 1 (Read)
0x0000000a   # 2: IOX 1563 ; FLP1 Load Control (Write)
0x0000000e   # 2: IOX 1565 ; FLP1 Load Pointer High (Write)
...

[0x00000000]> /ad EXIT            # Find all subroutine returns
[0x00000000]> /ad JPL             # Find all subroutine calls
```

### Search for Byte Patterns

```
[0x00000000]> /x d600             # Find bytes D6 00 (MON 0)
[0x00000000]> /x cc62             # Find bytes CC 62 (EXIT)
```

### Search for Strings

```
[0x00000000]> /z ERROR             # Search for ASCII string
[0x00000000]> iz                  # List detected strings
```

## Visual and Interactive Modes

### Visual Disassembly Mode

Press `V` then `p` to enter visual disassembly mode:

```
[0x00000000]> V
```

In visual mode:
- `p` / `P` -- cycle through display modes (hex, disasm, debug, etc.)
- `j` / `k` -- scroll down / up
- `J` / `K` -- scroll down / up by page
- `g` -- go to address (type address and press Enter)
- `Enter` -- follow jump/call target under cursor
- `u` -- undo seek (go back)
- `x` -- show cross-references to current address
- `X` -- show references from current address
- `:` -- enter command mode (type any Rizin command)
- `q` -- quit visual mode

### Visual Graph Mode (CFG)

Press `V` then `V` (or use `VV` directly) for the control flow graph:

```
[0x00000000]> VV @ fcn.0000037c
```

This shows the function as a graph of basic blocks connected by
branch arrows. Useful for understanding complex control flow.

In graph mode:
- `h` / `j` / `k` / `l` -- pan the graph
- `+` / `-` -- zoom in / out
- `g` -- go to a specific function
- `tab` -- switch between blocks
- `q` -- quit graph mode

### Panels Mode

Press `V` then `!` for panels mode, which shows multiple views
simultaneously (disassembly, hex, registers, etc.):

```
[0x00000000]> v
```

## Registers

The ND-100 register profile:

```
[0x00000000]> arp
=PC  pc
=SP  sp
=BP  b
=A0  a
=R0  a
gpr  a   .16  0   0    ; A register (accumulator)
gpr  t   .16  2   0    ; T register
gpr  x   .16  4   0    ; X register (index)
gpr  b   .16  6   0    ; B register (frame pointer)
gpr  l   .16  8   0    ; L register (link/return)
gpr  d   .16  10  0    ; D register
gpr  sp  .16  12  0    ; S register (stack pointer)
gpr  p   .16  14  0    ; P register (program counter)
gpr  pc  .16  16  0    ; PC (virtual, for Rizin)
```

## Working with Cutter (GUI)

Cutter is the official GUI for Rizin. Once the rz-nd100 plugins are
installed, Cutter automatically supports ND-100 files:

1. Open Cutter and load a BPUN or a.out16 file
2. Cutter auto-detects the format and sets the architecture
3. Click "Analyze" to run `aaa` (or configure analysis options)
4. Use the Graph view to see control flow graphs with branch arrows
5. The Disassembly view shows inline MON/IOX annotations
6. The Functions panel lists all discovered functions

For a.out16 files with symbols, the symbol names appear in the
Functions panel and in disassembly cross-references.

## Common Workflows

### Analyze a BPUN Bootstrap

```bash
$ rizin FLOPPY-MON-2010G.BPUN
[0x00000000]> iI                    # Check file info
[0x00000000]> aaa                   # Full analysis
[0x00000000]> afl                   # List functions
[0x00000000]> pdf @ entry0          # Disassemble entry point
[0x00000000]> /ad IOX               # Find all I/O instructions
[0x00000000]> /ad MON               # Find all monitor calls
[0x00000000]> VV @ entry0           # View CFG of entry function
```

### Analyze an a.out16 Executable

```bash
$ rizin boot.out
[0x00000000]> iI                    # Check file info
[0x00000000]> is                    # List symbols
[0x00000000]> aaa                   # Full analysis (uses prologue detection)
[0x00000000]> pdf @ sym.start       # Disassemble 'start' function
[0x00000000]> axt @ sym.start       # Who calls start?
```

### Analyze an a.out16 Object File (.o)

```bash
$ rizin module.o
[0x00000000]> ii                    # List imports (undefined externals)
[0x00000000]> ir                    # List relocations
[0x00000000]> is                    # List defined symbols
```

### Find I/O Device Usage

```bash
$ rizin FLOPPY-MON-2010G.BPUN
[0x00000000]> /ad IOX               # List all IOX instructions
```

The IOX annotations show the device name, register, and direction:

```
IOX   1562 ; FLP1 Read Status 1 (Read)
IOX   1563 ; FLP1 Load Control (Write)
IOX   1565 ; FLP1 Load Pointer High (Write)
IOX   1567 ; FLP1 Load Pointer Low (Write)
```

### Find SINTRAN III System Calls

```bash
$ rizin TPE-MON-100-B00.BPUN
[0x00000000]> /ad MON               # List all MON instructions
```

The MON annotations show the call name and description:

```
MON 0   ; LEAVE - ExitFromProgram
MON 1   ; INBT - InByte
MON 2   ; OUTBT - OutByte
MON 50  ; OPEN - OpenFile
MON 65  ; QERMS - ErrorMessage
MON 70  ; COMMND - CallCommand
```

### Batch Disassembly from Command Line

For scripting or quick inspection without entering the Rizin shell:

```bash
# Disassemble first 20 instructions
$ rizin -a nd100 -qc 'pd 20' file.BPUN

# Full analysis and function list
$ rizin -a nd100 -qc 'aaa; afl' file.BPUN

# Disassemble a specific function
$ rizin -a nd100 -qc 'aaa; pdf @ entry0' file.BPUN

# Search for MON calls
$ rizin -a nd100 -qc '/ad MON' file.BPUN

# Export function list as JSON
$ rizin -a nd100 -qc 'aaa; aflj' file.BPUN
```

## Quick Reference

| Command | Description |
|---------|-------------|
| `iI` | File info (arch, bits, endianness) |
| `ie` | Entry points |
| `iS` | Sections |
| `is` | Symbols |
| `ii` | Imports (undefined externals in .o files) |
| `ir` | Relocations (.o files only) |
| `aaa` | Full auto-analysis (with prologue detection) |
| `afl` | List functions |
| `aflc` | Count functions |
| `pdf` | Disassemble current function |
| `pd N` | Disassemble N instructions |
| `s ADDR` | Seek to address |
| `ao N` | Analyze N opcodes (show type, jump, fail) |
| `axt ADDR` | Cross-references to address |
| `axf ADDR` | References from address |
| `/ad PATTERN` | Search for disassembly pattern |
| `/x HEX` | Search for hex bytes |
| `/z STRING` | Search for ASCII string |
| `V` | Enter visual mode |
| `VV` | Enter visual graph mode (CFG) |
| `v` | Enter panels mode |
| `q` | Quit (from any mode) |

## Octal vs Hex in ND-100

The ND-100 traditionally uses octal notation. Rizin defaults to
hexadecimal, but the disassembler outputs operands in octal to match
ND-100 conventions. Addresses in Rizin are always shown in hex.

To print a value in different bases, use the `%` command:

```
[0x00000000]> % 0x1000
int32   4096
uint32  4096
hex     0x1000
octal   010000
...
```
