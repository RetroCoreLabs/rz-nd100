/*
 * iodevs.c - ND-100 I/O device register lookup table
 *
 * Generated from io-devices.json (NDGen specs).
 * Maps IOX addresses to device names, register descriptions,
 * and bit field summaries.
 *
 * All addresses are octal (matching IOX instruction encoding).
 */

#include "iodevs.h"
#include <stddef.h>

static const struct iox_device iox_devices[] = {
	/* RTC1 - Real-Time Clock unit 1 (octal 010-013) */
	{ 00010, "RTC1", "Read Data Register", "Read", "" },
	{ 00011, "RTC1", "Clear Counter", "Write", "" },
	{ 00012, "RTC1", "Read Status", "Read", "b0=IntEna; b2=ExtHold; b3=Ready" },
	{ 00013, "RTC1", "Write Control", "Write", "b0=IntEna; b10-11=Freq; b13=ClrRdy; b15=Restart" },

	/* RTC2 - Real-Time Clock unit 2 (octal 014-017) */
	{ 00014, "RTC2", "Read Data Register", "Read", "" },
	{ 00015, "RTC2", "Clear Counter", "Write", "" },
	{ 00016, "RTC2", "Read Status", "Read", "b0=IntEna; b2=ExtHold; b3=Ready" },
	{ 00017, "RTC2", "Write Control", "Write", "b0=IntEna; b10-11=Freq; b13=ClrRdy; b15=Restart" },

	/* RTC3 - Real-Time Clock unit 3 (octal 020-023) */
	{ 00020, "RTC3", "Read Data Register", "Read", "" },
	{ 00021, "RTC3", "Clear Counter", "Write", "" },
	{ 00022, "RTC3", "Read Status", "Read", "b0=IntEna; b2=ExtHold; b3=Ready" },
	{ 00023, "RTC3", "Write Control", "Write", "b0=IntEna; b10-11=Freq; b13=ClrRdy; b15=Restart" },

	/* ND500_1 - ND-500 Interface unit 1 (octal 060-077) */
	{ 00060, "ND500_1", "Read MAR x2", "Read", "" },
	{ 00061, "ND500_1", "Load MAR x2", "Write", "" },
	{ 00062, "ND500_1", "Read Status", "Read", "b0=IntEna; b2=Busy; b3=Finished; b4=Error" },
	{ 00063, "ND500_1", "Load Status (test)", "Write", "" },
	{ 00064, "ND500_1", "Read Control", "Read", "" },
	{ 00065, "ND500_1", "Load Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear" },
	{ 00066, "ND500_1", "Master Clear", "Write/Read", "" },
	{ 00067, "ND500_1", "Terminate", "Write", "" },
	{ 00070, "ND500_1", "Read TAG-IN", "Read", "" },
	{ 00071, "ND500_1", "Write TAG-OUT", "Write", "" },
	{ 00072, "ND500_1", "Read Lower Limit", "Read", "" },
	{ 00073, "ND500_1", "Write DATAX", "Write", "" },
	{ 00074, "ND500_1", "Read Locked", "Read", "" },
	{ 00075, "ND500_1", "Write Data", "Write", "" },
	{ 00076, "ND500_1", "Read Locked", "Read", "" },
	{ 00077, "ND500_1", "Return Gate (RETG5)", "Write", "b1=Stop microclock" },

	/* LP3 - Line Printer unit 3 (octal 0160-0163) */
	{ 00160, "LP3", "Read Data", "Read", "" },
	{ 00161, "LP3", "Write Data", "Write", "" },
	{ 00162, "LP3", "Read Status", "Read", "b0=IntEna; b3=Ready; b4=Error; b5=NotReady; b6=NoPaper" },
	{ 00163, "LP3", "Write Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear" },

	/* LP4 - Line Printer unit 4 (octal 0164-0167) */
	{ 00164, "LP4", "Read Data", "Read", "" },
	{ 00165, "LP4", "Write Data", "Write", "" },
	{ 00166, "LP4", "Read Status", "Read", "b0=IntEna; b3=Ready; b4=Error; b5=NotReady; b6=NoPaper" },
	{ 00167, "LP4", "Write Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear" },

	/* LP5 - Line Printer unit 5 (octal 0170-0173) */
	{ 00170, "LP5", "Read Data", "Read", "" },
	{ 00171, "LP5", "Write Data", "Write", "" },
	{ 00172, "LP5", "Read Status", "Read", "b0=IntEna; b3=Ready; b4=Error; b5=NotReady; b6=NoPaper" },
	{ 00173, "LP5", "Write Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear" },

	/* LP6 - Line Printer unit 6 (octal 0174-0177) */
	{ 00174, "LP6", "Read Data", "Read", "" },
	{ 00175, "LP6", "Write Data", "Write", "" },
	{ 00176, "LP6", "Read Status", "Read", "b0=IntEna; b3=Ready; b4=Error; b5=NotReady; b6=NoPaper" },
	{ 00177, "LP6", "Write Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear" },

	/* CON - Console Terminal (octal 0300-0307) */
	{ 00300, "CON", "Read Input Data", "Read", "" },
	{ 00301, "CON", "Write (NOP)", "Write", "" },
	{ 00302, "CON", "Read Input Status", "Read", "b0=IntEna; b2=Active; b3=Ready; b4=ErrOR; b5=Frame; b6=Parity; b7=Overrun" },
	{ 00303, "CON", "Write Input Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear; b11-12=CharLen; b13=StopBits; b14=Parity" },
	{ 00304, "CON", "Read (Returns 0)", "Read", "" },
	{ 00305, "CON", "Write Output Data", "Write", "" },
	{ 00306, "CON", "Read Output Status", "Read", "b0=IntEna; b3=Ready" },
	{ 00307, "CON", "Write Output Control", "Write", "b0=IntEna" },

	/* PTR1 - Paper Tape Reader unit 1 (octal 0400-0403) */
	{ 00400, "PTR1", "Read Data", "Read", "" },
	{ 00401, "PTR1", "Write Data Buffer", "Write", "" },
	{ 00402, "PTR1", "Read Status", "Read", "b0=IntEna; b2=Active; b3=Ready" },
	{ 00403, "PTR1", "Write Control", "Write", "b0=IntEna; b2=Activate; b3=Ready; b4=Clear" },

	/* PTR2 - Paper Tape Reader unit 2 (octal 0404-0407) */
	{ 00404, "PTR2", "Read Data", "Read", "" },
	{ 00405, "PTR2", "Write Data Buffer", "Write", "" },
	{ 00406, "PTR2", "Read Status", "Read", "b0=IntEna; b2=Active; b3=Ready" },
	{ 00407, "PTR2", "Write Control", "Write", "b0=IntEna; b2=Activate; b3=Ready; b4=Clear" },

	/* LP1 - Line Printer unit 1 (octal 0430-0433) */
	{ 00430, "LP1", "Read Data", "Read", "" },
	{ 00431, "LP1", "Write Data", "Write", "" },
	{ 00432, "LP1", "Read Status", "Read", "b0=IntEna; b3=Ready; b4=Error; b5=NotReady; b6=NoPaper" },
	{ 00433, "LP1", "Write Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear" },

	/* LP2 - Line Printer unit 2 (octal 0434-0437) */
	{ 00434, "LP2", "Read Data", "Read", "" },
	{ 00435, "LP2", "Write Data", "Write", "" },
	{ 00436, "LP2", "Read Status", "Read", "b0=IntEna; b3=Ready; b4=Error; b5=NotReady; b6=NoPaper" },
	{ 00437, "LP2", "Write Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear" },

	/* SMD3 - SMD Disk Controller unit 3 (octal 0540-0547) */
	{ 00540, "SMD3", "Read Core Address", "Read", "" },
	{ 00541, "SMD3", "Load Core Address", "Write", "" },
	{ 00542, "SMD3", "Read Seek Cond/ECC Count", "Read", "b0-7=SeekComplete; b8-10=Unit; b11=SeekErr; b13=Correctable" },
	{ 00543, "SMD3", "Load Block Address", "Write", "" },
	{ 00544, "SMD3", "Read Status/ECC Pattern", "Read", "b0=IntEna; b2=Active; b3=Ready; b4=HwErr; b13=NotReady; b14=OnCyl; b15=CWR" },
	{ 00545, "SMD3", "Load Control Word", "Write", "b0=IntEna; b2=Active; b4=Clear; b7-9=Unit; b11-14=OpCode; b15=CWR" },
	{ 00546, "SMD3", "Read Block Address", "Read", "" },
	{ 00547, "SMD3", "Load Word Count/ECC Ctrl", "Write", "" },

	/* SMD4 - SMD Disk Controller unit 4 (octal 0550-0557) */
	{ 00550, "SMD4", "Read Core Address", "Read", "" },
	{ 00551, "SMD4", "Load Core Address", "Write", "" },
	{ 00552, "SMD4", "Read Seek Cond/ECC Count", "Read", "b0-7=SeekComplete; b8-10=Unit; b11=SeekErr; b13=Correctable" },
	{ 00553, "SMD4", "Load Block Address", "Write", "" },
	{ 00554, "SMD4", "Read Status/ECC Pattern", "Read", "b0=IntEna; b2=Active; b3=Ready; b4=HwErr; b13=NotReady; b14=OnCyl; b15=CWR" },
	{ 00555, "SMD4", "Load Control Word", "Write", "b0=IntEna; b2=Active; b4=Clear; b7-9=Unit; b11-14=OpCode; b15=CWR" },
	{ 00556, "SMD4", "Read Block Address", "Read", "" },
	{ 00557, "SMD4", "Load Word Count/ECC Ctrl", "Write", "" },

	/* ND500_5 - ND-500 Interface unit 5 (octal 0560-0577) */
	{ 00560, "ND500_5", "Read MAR x2", "Read", "" },
	{ 00561, "ND500_5", "Load MAR x2", "Write", "" },
	{ 00562, "ND500_5", "Read Status", "Read", "b0=IntEna; b2=Busy; b3=Finished; b4=Error" },
	{ 00563, "ND500_5", "Load Status (test)", "Write", "" },
	{ 00564, "ND500_5", "Read Control", "Read", "" },
	{ 00565, "ND500_5", "Load Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear" },
	{ 00566, "ND500_5", "Master Clear", "Write/Read", "" },
	{ 00567, "ND500_5", "Terminate", "Write", "" },
	{ 00570, "ND500_5", "Read TAG-IN", "Read", "" },
	{ 00571, "ND500_5", "Write TAG-OUT", "Write", "" },
	{ 00572, "ND500_5", "Read Lower Limit", "Read", "" },
	{ 00573, "ND500_5", "Write DATAX", "Write", "" },
	{ 00574, "ND500_5", "Read Locked", "Read", "" },
	{ 00575, "ND500_5", "Write Data", "Write", "" },
	{ 00576, "ND500_5", "Read Locked", "Read", "" },
	{ 00577, "ND500_5", "Return Gate (RETG5)", "Write", "b1=Stop microclock" },

	/* ND500_3 - ND-500 Interface unit 3 (octal 0660-0677) */
	{ 00660, "ND500_3", "Read MAR x2", "Read", "" },
	{ 00661, "ND500_3", "Load MAR x2", "Write", "" },
	{ 00662, "ND500_3", "Read Status", "Read", "b0=IntEna; b2=Busy; b3=Finished; b4=Error" },
	{ 00663, "ND500_3", "Load Status (test)", "Write", "" },
	{ 00664, "ND500_3", "Read Control", "Read", "" },
	{ 00665, "ND500_3", "Load Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear" },
	{ 00666, "ND500_3", "Master Clear", "Write/Read", "" },
	{ 00667, "ND500_3", "Terminate", "Write", "" },
	{ 00670, "ND500_3", "Read TAG-IN", "Read", "" },
	{ 00671, "ND500_3", "Write TAG-OUT", "Write", "" },
	{ 00672, "ND500_3", "Read Lower Limit", "Read", "" },
	{ 00673, "ND500_3", "Write DATAX", "Write", "" },
	{ 00674, "ND500_3", "Read Locked", "Read", "" },
	{ 00675, "ND500_3", "Write Data", "Write", "" },
	{ 00676, "ND500_3", "Read Locked", "Read", "" },
	{ 00677, "ND500_3", "Return Gate (RETG5)", "Write", "b1=Stop microclock" },

	/* ND500_4 - ND-500 Interface unit 4 (octal 0760-0777) */
	{ 00760, "ND500_4", "Read MAR x2", "Read", "" },
	{ 00761, "ND500_4", "Load MAR x2", "Write", "" },
	{ 00762, "ND500_4", "Read Status", "Read", "b0=IntEna; b2=Busy; b3=Finished; b4=Error" },
	{ 00763, "ND500_4", "Load Status (test)", "Write", "" },
	{ 00764, "ND500_4", "Read Control", "Read", "" },
	{ 00765, "ND500_4", "Load Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear" },
	{ 00766, "ND500_4", "Master Clear", "Write/Read", "" },
	{ 00767, "ND500_4", "Terminate", "Write", "" },
	{ 00770, "ND500_4", "Read TAG-IN", "Read", "" },
	{ 00771, "ND500_4", "Write TAG-OUT", "Write", "" },
	{ 00772, "ND500_4", "Read Lower Limit", "Read", "" },
	{ 00773, "ND500_4", "Write DATAX", "Write", "" },
	{ 00774, "ND500_4", "Read Locked", "Read", "" },
	{ 00775, "ND500_4", "Write Data", "Write", "" },
	{ 00776, "ND500_4", "Read Locked", "Read", "" },
	{ 00777, "ND500_4", "Return Gate (RETG5)", "Write", "b1=Stop microclock" },

	/* ND500_2 - ND-500 Interface unit 2 (octal 01060-01077) */
	{ 01060, "ND500_2", "Read MAR x2", "Read", "" },
	{ 01061, "ND500_2", "Load MAR x2", "Write", "" },
	{ 01062, "ND500_2", "Read Status", "Read", "b0=IntEna; b2=Busy; b3=Finished; b4=Error" },
	{ 01063, "ND500_2", "Load Status (test)", "Write", "" },
	{ 01064, "ND500_2", "Read Control", "Read", "" },
	{ 01065, "ND500_2", "Load Control", "Write", "b0=IntEna; b2=Activate; b3=Test; b4=Clear" },
	{ 01066, "ND500_2", "Master Clear", "Write/Read", "" },
	{ 01067, "ND500_2", "Terminate", "Write", "" },
	{ 01070, "ND500_2", "Read TAG-IN", "Read", "" },
	{ 01071, "ND500_2", "Write TAG-OUT", "Write", "" },
	{ 01072, "ND500_2", "Read Lower Limit", "Read", "" },
	{ 01073, "ND500_2", "Write DATAX", "Write", "" },
	{ 01074, "ND500_2", "Read Locked", "Read", "" },
	{ 01075, "ND500_2", "Write Data", "Write", "" },
	{ 01076, "ND500_2", "Read Locked", "Read", "" },
	{ 01077, "ND500_2", "Return Gate (RETG5)", "Write", "b1=Stop microclock" },

	/* SMD1 - SMD Disk Controller unit 1 (octal 01540-01547) */
	{ 01540, "SMD1", "Read Core Address", "Read", "" },
	{ 01541, "SMD1", "Load Core Address", "Write", "" },
	{ 01542, "SMD1", "Read Seek Cond/ECC Count", "Read", "b0-7=SeekComplete; b8-10=Unit; b11=SeekErr; b13=Correctable" },
	{ 01543, "SMD1", "Load Block Address", "Write", "" },
	{ 01544, "SMD1", "Read Status/ECC Pattern", "Read", "b0=IntEna; b2=Active; b3=Ready; b4=HwErr; b13=NotReady; b14=OnCyl; b15=CWR" },
	{ 01545, "SMD1", "Load Control Word", "Write", "b0=IntEna; b2=Active; b4=Clear; b7-9=Unit; b11-14=OpCode; b15=CWR" },
	{ 01546, "SMD1", "Read Block Address", "Read", "" },
	{ 01547, "SMD1", "Load Word Count/ECC Ctrl", "Write", "" },

	/* SMD2 - SMD Disk Controller unit 2 (octal 01550-01557) */
	{ 01550, "SMD2", "Read Core Address", "Read", "" },
	{ 01551, "SMD2", "Load Core Address", "Write", "" },
	{ 01552, "SMD2", "Read Seek Cond/ECC Count", "Read", "b0-7=SeekComplete; b8-10=Unit; b11=SeekErr; b13=Correctable" },
	{ 01553, "SMD2", "Load Block Address", "Write", "" },
	{ 01554, "SMD2", "Read Status/ECC Pattern", "Read", "b0=IntEna; b2=Active; b3=Ready; b4=HwErr; b13=NotReady; b14=OnCyl; b15=CWR" },
	{ 01555, "SMD2", "Load Control Word", "Write", "b0=IntEna; b2=Active; b4=Clear; b7-9=Unit; b11-14=OpCode; b15=CWR" },
	{ 01556, "SMD2", "Read Block Address", "Read", "" },
	{ 01557, "SMD2", "Load Word Count/ECC Ctrl", "Write", "" },

	/* FLP1 - Floppy DMA Controller unit 1 (octal 01560-01567) */
	{ 01560, "FLP1", "Read Data", "Read", "" },
	{ 01561, "FLP1", "(Not Used)", "", "" },
	{ 01562, "FLP1", "Read Status 1", "Read", "b1=IntEna; b2=Active; b3=Ready; b4=ErrOR; b5=DelRec; b7=HardErr; b15=DualDensity" },
	{ 01563, "FLP1", "Load Control", "Write", "b1=IntEna; b2=Autoload; b3=Test; b4=Clear; b5=Streamer; b8=ExecCmd" },
	{ 01564, "FLP1", "Read Status 2", "Read", "b0-1=BytesPerSec; b2=DblSided; b3=DblDensity" },
	{ 01565, "FLP1", "Load Pointer High", "Write", "" },
	{ 01566, "FLP1", "(Not Used)", "", "" },
	{ 01567, "FLP1", "Load Pointer Low", "Write", "" },

	/* FLP2 - Floppy DMA Controller unit 2 (octal 01570-01577) */
	{ 01570, "FLP2", "Read Data", "Read", "" },
	{ 01571, "FLP2", "(Not Used)", "", "" },
	{ 01572, "FLP2", "Read Status 1", "Read", "b1=IntEna; b2=Active; b3=Ready; b4=ErrOR; b5=DelRec; b7=HardErr; b15=DualDensity" },
	{ 01573, "FLP2", "Load Control", "Write", "b1=IntEna; b2=Autoload; b3=Test; b4=Clear; b5=Streamer; b8=ExecCmd" },
	{ 01574, "FLP2", "Read Status 2", "Read", "b0-1=BytesPerSec; b2=DblSided; b3=DblDensity" },
	{ 01575, "FLP2", "Load Pointer High", "Write", "" },
	{ 01576, "FLP2", "(Not Used)", "", "" },
	{ 01577, "FLP2", "Load Pointer Low", "Write", "" },

	{ 0, NULL, NULL, NULL, NULL } /* sentinel */
};

const struct iox_device *
iox_lookup(int addr)
{
	const struct iox_device *d;

	for (d = iox_devices; d->device != NULL; d++) {
		if (d->address == addr)
			return d;
	}
	return NULL;
}
