# Getting Started with Rizin for ND-100

A practical guide to reverse-engineering Norsk Data ND-100/ND-110 binaries
using Rizin and the rz-nd100 plugin suite.

## Prerequisites

- Rizin 0.8.0 or later installed
- rz-nd100 plugins built and installed (see `INSTALL.md`)

Verify the plugins are loaded:

```
$ rz-asm -L | grep nd100
adAe_ 16         nd100       LGPL3   Norsk Data ND-100/ND-110 disassembler and assembler

$ rizin -qc 'iL' /dev/null | grep -E 'bpun|aout16'
bin  aout16      Norsk Data ND-100 a.out16 format
bin  bpun        Norsk Data BPUN bootstrap format
```

You should see the disassembler/assembler/analysis (`nd100`) and two
binary loaders (`bpun` and `aout16`). The `A` flag in `adAe_` confirms
assembler support.

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

### Disassembly

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

### Assembly

Assemble ND-100 instructions to binary:

```
$ rz-asm -a nd100 'LDA ,B -4'
fc49

$ rz-asm -a nd100 'BSKP ONE 10 DA'
8dfa

$ rz-asm -a nd100 'RADD CLD SA DA'
2dd0

$ rz-asm -a nd100 'MON 101'
41d6
```

Two syntax styles are supported for addressing modes:

```
$ rz-asm -a nd100 'LDA ,B -4'      # Rizin disassembly format
fc49
$ rz-asm -a nd100 'LDA -4,B'       # nd100-as assembler format
fc49
```

Both produce the same encoding. Round-trip is guaranteed:

```
$ rz-asm -a nd100 'LDA ,B -4' | xargs rz-asm -a nd100 -d
LDA ,B -4
```

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

[0x00000000]> ih          # Header display (a.out16 files)
[0x00000000]> iH          # Header fields (a.out16 files)
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

### Pseudo-Code Output

Enable C-like pseudo-code translation:

```
[0x00000000]> e asm.pseudo=true
[0x00000000]> pd 6
            0x00000000      a = 5
            0x00000002      a = *(b + 10)
            0x00000004      *(b + 5) = a
            0x00000006      if (a > 0) goto 0x14
            0x00000008      TRAP(LEAVE)
            0x0000000a      a += *(b + 3)
```

Or use `pdc` for full function pseudo-code:

```
[0x00000000]> aaa
[0x00000000]> pdc @ entry0
```

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
- **Branch arrows** (`+--` / `+->`) for conditional jumps (JAN, JAZ, SKP, BSKP, MIN, etc.)
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
family: cpu
```

The `type` field shows how the analysis plugin classified the
instruction:
- `jmp` -- unconditional jump (JMP)
- `cjmp` -- conditional jump (JAP, JAN, SKP, BSKP, MIN, etc.)
- `call` -- subroutine call (JPL)
- `ret` -- return (EXIT, LEAVE, ELEAV)
- `swi` -- software interrupt (MON)
- `io` -- I/O operation (IOX, IOT)
- `nop` -- no operation (ROP NOOP, IOF, ION, etc.)

The `family` field classifies the instruction group:
- `cpu` -- general CPU instructions
- `fpu` -- floating-point (FAD, FSB, FMU, FDV)
- `io` -- I/O instructions (IOX, IOT, IOXT)
- `priv` -- privileged/system instructions (TRA, TRR, MCL, MST, OPCOM, etc.)

## ESIL Emulation

ESIL (Evaluable Strings Intermediate Language) allows stepping through
ND-100 code instruction by instruction:

```
[0x00000000]> aei           # Initialize ESIL VM
[0x00000000]> aeim          # Initialize ESIL memory
[0x00000000]> aer a=0x42    # Set register A to 0x42
[0x00000000]> aes           # Step one instruction
[0x00000000]> aes           # Step another
[0x00000000]> ar            # Show all registers
s = 0x0000
d = 0x0000
p = 0x0000
b = 0x0000
l = 0x0000
a = 0x0042
t = 0x0000
x = 0x0000
pc = 0x0004
```

ESIL strings are generated for:
- All memory reference instructions (LDA, STA, ADD, SUB, AND, ORA, etc.) with all addressing modes
- Branch conditions (JAP, JAN, JAZ, JAF, JPC, JNC, JXZ, JXN)
- Skip comparisons (SKP IF DA GRE SA, etc.)
- Register operations (RADD, RADD CLD)
- Shift instructions (SHT, SHD, SHA, SAD)
- Argument instructions (SAA, AAA, SAB, AAB, etc.)
- MON trap calls
- Memory increment/decrement (MIN, DNZ)

To view the ESIL string for an instruction:

```
[0x00000000]> aoe @ 0x100   # Show ESIL at address
```

## Assembler

### Using the Assembler from Rizin

Inside Rizin, use `wa` to write assembled instructions:

```
[0x00000000]> wa LDA ,B -4
Written 2 byte(s) (LDA ,B -4) = wx fc49
```

### Supported Instruction Categories

The assembler supports the complete ND-100/ND-110 instruction set:

**Memory reference** (all 8 addressing modes):
`STZ`, `STA`, `STT`, `STX`, `STD`, `LDD`, `STF`, `LDF`, `MIN`,
`LDA`, `LDT`, `LDX`, `ADD`, `SUB`, `AND`, `ORA`, `FAD`, `FSB`,
`FMU`, `FDV`, `MPY`, `JMP`, `JPL`

**Conditional branches**: `JAP`, `JAN`, `JAZ`, `JAF`, `JPC`, `JNC`, `JXZ`, `JXN`

**Argument instructions**: `SAB`, `SAA`, `SAT`, `SAX`, `AAB`, `AAA`, `AAT`, `AAX`

**Register operations** (with CLD/CM1/AD1/ADC modifiers):
`RADD`, `RSUB`, `SWAP`, `RAND`, `REXO`, `RORA`, `COPY`, `RMPY`, `RDIV`, `RCLR`, `RINC`, `RDCR`

**Skip instructions**: `SKP IF <dst> <cond> <src>`

**Bit operations**: `BSET`, `BSKP` (with ZRO/ONE/BCM/BAC conditions),
`BSTC`, `BSTA`, `BLDC`, `BLDA`, `BANC`, `BAND`, `BORC`, `BORA`

**Shift instructions**: `SHT`, `SHD`, `SHA`, `SAD` (with ROT/ZIN/LIN/SHR)

**I/O**: `IOX`, `IOT`, `MON`

**Internal registers**: `TRA`, `TRR`, `MCL`, `MST`, `IRW`, `IRR`

**Privileged**: `IDENT PL10/PL11/PL12/PL13`, `EXR`,
`LDATX`, `LDXTX`, `LDDTX`, `LDBTX`, `STATX`, `STZTX`, `STDTX`

**ND-110**: `WGLOB`, `RGLOB`, `INSPL`, `REMPL`, `CNREK`, `CLPT`, `ENPT`, `REPT`,
`LBIT`, `SBITP`, `LBYTP`, `SBYTP`, `TSETP`, `RDUSP`,
`LASB`, `SASB`, `LACB`, `SACB`, `LXSB`, `LXCB`, `SZSB`, `SZCB`

**Fixed-word**: `EXIT`, `LEAVE`, `ELEAV`, `ENTR`, `INIT`, `OPCOM`, `IOF`, `ION`,
`POF`, `PIOF`, `PON`, `PION`, `SEX`, `REX`, `WAIT`, `HALT`, `IOXT`, `EXAM`, `DEPO`,
`ADDD`, `SUBD`, `COMD`, `TSET`, `PACK`, `UPACK`, `SHDE`, `RDUS`, `BFILL`,
`MOVB`, `MOVBF`, `VERSN`, `LBYT`, `SBYT`, `GECO`, `MOVEW`, `LWCS`, `MIX3`,
`SETPT`, `CLEPT`, `CLNREENT`, `CHREENT-PAGES`, `CLEPU`, `ROP NOOP`,
`SRB`, `LRB`, `NLZ`, `DNZ`

### Addressing Mode Syntax

Both Rizin disassembly format and nd100-as assembler format are accepted:

| Rizin format | nd100-as format | Mode |
|---|---|---|
| `LDA 10` | `LDA 10` | Direct |
| `LDA ,B 10` | `LDA 10,B` | B-relative |
| `LDA I 10` | `LDA I 10` | Indirect |
| `LDA I ,B 10` | `LDA I 10,B` | Indirect B-relative |
| `LDA ,X 10` | `LDA 10,X` | X-indexed |
| `LDA ,X ,B 10` | `LDA 10,B,X` | X-indexed B-relative |
| `LDA I ,X 10` | `LDA I 10,X` | Indirect X-indexed |
| `LDA I ,B ,X 10` | `LDA I 10,B,X` | Indirect B-relative X-indexed |

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
[0x00000000]> ar
s  = 0x0000    ; S register (status)
d  = 0x0000    ; D register
p  = 0x0000    ; P register (program counter, hardware)
b  = 0x0000    ; B register (frame pointer)
l  = 0x0000    ; L register (link/return address)
a  = 0x0000    ; A register (accumulator)
t  = 0x0000    ; T register
x  = 0x0000    ; X register (index)
pc = 0x0000    ; PC (virtual, for Rizin)
```

**Note:** The ND-100 has no hardware stack. There is no stack pointer
register and no PUSH/POP instructions. Subroutine calls (JPL) save the
return address in the L register. The B register serves as a frame
pointer in the ENTR/LEAVE calling convention, where local variables and
saved registers are accessed via B-relative addressing modes.

Rizin's `=SP` is mapped to the B register for frame variable detection.

## Working with Cutter (GUI)

Cutter is the official GUI for Rizin. Once the rz-nd100 plugins are
installed, Cutter automatically supports ND-100 files:

1. Open Cutter and load a BPUN or a.out16 file
2. Cutter auto-detects the format and sets the architecture
3. Click "Analyze" to run `aaa` (or configure analysis options)
4. Use the Graph view to see control flow graphs with branch arrows
5. The Disassembly view shows inline MON/IOX annotations
6. Enable pseudo-code with `e asm.pseudo=true` in the console
7. The Functions panel lists all discovered functions

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
[0x00000000]> ih                    # Display a.out16 header
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

### ESIL Stepping

```bash
$ rizin -a nd100 -b 16 firmware.bin
[0x00000000]> aei                   # Initialize ESIL
[0x00000000]> aeim                  # Initialize ESIL memory
[0x00000000]> aer a=0xff            # Set accumulator
[0x00000000]> aer b=0x100           # Set frame pointer
[0x00000000]> aes                   # Step one instruction
[0x00000000]> ar                    # Show registers after step
[0x00000000]> aec                   # Continue until break/end
```

### Assemble and Patch

```bash
$ rizin -w firmware.bin             # Open in write mode
[0x00000000]> wa JMP 10             # Write assembled instruction
[0x00000000]> wa ROP NOOP           # Write NOP
[0x00000000]> wao nop               # Replace current instruction with NOP
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

# Assemble from command line
$ rz-asm -a nd100 'LDA ,B -4'
$ rz-asm -a nd100 'BSKP ONE 10 DA'
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
| `ih` | Header display (a.out16) |
| `iH` | Header fields (a.out16) |
| `aaa` | Full auto-analysis (with prologue detection) |
| `afl` | List functions |
| `aflc` | Count functions |
| `pdf` | Disassemble current function |
| `pdc` | Pseudo-code of current function |
| `pd N` | Disassemble N instructions |
| `s ADDR` | Seek to address |
| `ao N` | Analyze N opcodes (show type, jump, fail, family) |
| `axt ADDR` | Cross-references to address |
| `axf ADDR` | References from address |
| `aei` | Initialize ESIL VM |
| `aeim` | Initialize ESIL memory |
| `aes` | ESIL step one instruction |
| `aec` | ESIL continue |
| `ar` | Show registers |
| `wa INSN` | Write assembled instruction |
| `e asm.pseudo=true` | Enable pseudo-code output |
| `e asm.cpu=nd110` | Enable ND-110 extended instructions |
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
