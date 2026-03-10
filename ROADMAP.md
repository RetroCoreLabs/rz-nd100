# rz-nd100 Enhancement Roadmap

## Build Order (each phase builds on the previous)

### Phase 1: Foundation -- Op Metadata Enrichment
- [x] Richer op types (LOAD, STORE, ADD, IO, NOP etc.)
- [x] Op family classification (CPU/FPU/IO/PRIV)
- [x] Condition type for conditional instructions
- [x] Mnemonic via MASK_DISASM
- [x] Address bits callback

### Phase 2: Operand & Stack Analysis
- [x] Stack pointer tracking (stackop/stackptr)
- [x] Operand value analysis (src/dst/ptr/val/reg)

### Phase 3: Assembler
- [x] Instruction encoder (.assemble callback)
- [x] All memory-reference instructions with all 8 addressing modes
- [x] Conditional branches, argument instructions, MON/IOX/IOT
- [x] SKP with IF/condition/registers
- [x] Register operations (RADD/SWAP/RAND/REXO/RORA/RSUB with modifiers)
- [x] Shift instructions (SHT/SHD/SHA/SAD with ROT/ZIN/LIN/SHR)
- [x] TRA/TRR/MCL/MST with internal register names
- [x] COPY, RMPY, RDIV, SRB, LRB, ROP NOOP
- [x] nd100-as trailing comma syntax (LDA -4,B)
- [x] EXR with register argument
- [x] IRW/IRR with level and register
- [x] IDENT PL10/PL11/PL12/PL13
- [x] RCLR, RINC, RDCR register aliases
- [x] Physical memory: LDATX, LDXTX, LDDTX, LDBTX, STATX, STZTX, STDTX
- [x] Bit operations: BSET/BSKP with ZRO/ONE/BCM/BAC conditions
- [x] Single-name bit ops: BSTC/BSTA/BLDC/BLDA/BANC/BAND/BORC/BORA
- [x] ND-110 instructions (WGLOB, RGLOB, INSPL, REMPL, CNREK, etc.)
- [x] ND-110 delta instructions (LASB, SASB, LACB, SACB, LXSB, LXCB, SZSB, SZCB)
- [x] All fixed-word instructions (MIX3, HALT, SETPT, CLEPT, CLNREENT, CLEPU, VERSN)

### Phase 4: ESIL Emulation
- [x] ESIL string generation for all instruction classes
- [x] Memory reference load/store/arithmetic ESIL
- [x] Branch/skip condition ESIL
- [x] Register operation ESIL (RADD, RADD CLD)
- [x] Shift instruction ESIL
- [x] Argument instruction ESIL (SAA/AAA etc.)
- [x] MON trap ESIL
- [ ] ESIL lifecycle callbacks (init/trap/fini)

### Phase 5: Calling Convention & Stack Frames
- [x] Register profile (a, t, x, b, l, d, sp, p, pc)
- [x] Function prologue detection (COPY SL DA, ENTR, INIT)
- [x] Stack tracking for JPL/EXIT/LEAVE/ELEAV/ENTR/INIT
- [ ] Formal calling convention definition (cc)
- [ ] Stack variable detection (B-relative accesses)

### Phase 6: Pseudo-Code
- [x] RzParsePlugin for C-like pdc output
- [x] MON/IOX annotation in pseudo-code

### Phase 7: Binary Format Extras
- [x] a.out16 header display (.header)
- [x] a.out16 field descriptions (.fields)
- [x] a.out16 special symbols / main detection (.binsym)
- [ ] a.out16 relocation patching (.patch_relocs)
- [ ] BPUN multi-section support

### Phase 8: RzIL Lifting (future)
- [ ] IL configuration
- [ ] IL lifting per instruction
