/*
 * moncalls.c - SINTRAN III MON call lookup table
 *
 * Generated from mon-calls.json (NDGen specs).
 * Maps MON call numbers to names and descriptions.
 *
 * All numbers are decimal (matching MON instruction encoding).
 */

#include "moncalls.h"
#include <stddef.h>

static const struct mon_call mon_call_table[] = {
	{ 0, "LEAVE", "ExitFromProgram" },	/* 000B */
	{ 1, "INBT", "InByte" },	/* 001B */
	{ 2, "OUTBT", "OutByte" },	/* 002B */
	{ 3, "ECHOM", "SetEcho" },	/* 003B */
	{ 4, "BRKM", "SetBreak" },	/* 004B */
	{ 5, "RDISK", "ReadScratchFile" },	/* 005B */
	{ 6, "WDISK", "WriteScratchFile" },	/* 006B */
	{ 7, "RPAGE", "ReadBlock" },	/* 007B */
	{ 8, "WPAGE", "WriteBlock" },	/* 010B */
	{ 9, "TIME", "GetBasicTime" },	/* 011B */
	{ 10, "SETCM", "SetCommandBuffer" },	/* 012B */
	{ 11, "CIBUF", "ClearInBuffer" },	/* 013B */
	{ 12, "COBUF", "ClearOutBuffer" },	/* 014B */
	{ 14, "MGTTY", "GetTerminalType" },	/* 016B */
	{ 15, "MSTTY", "SetTerminalType" },	/* 017B */
	{ 17, "M8INB", "InUpTo8Bytes" },	/* 021B */
	{ 18, "M8OUT", "OutUpTo8Bytes" },	/* 022B */
	{ 19, "B8INB", "In8Bytes" },	/* 023B */
	{ 20, "B8OUT", "Out8Bytes" },	/* 024B */
	{ 22, "LASTC", "GetLastByte" },	/* 026B */
	{ 23, "RTDSC", "GetRTDescr" },	/* 027B */
	{ 24, "GETRT", "GetOwnRTAddress" },	/* 030B */
	{ 25, "EXIOX", "IOInstruction" },	/* 031B */
	{ 26, "MSG", "OutMessage" },	/* 032B */
	{ 27, "ALTON", "AltPageTable" },	/* 033B */
	{ 28, "ALTOFF", "NormalPageTable" },	/* 034B */
	{ 29, "IOUT", "OutNumber" },	/* 035B */
	{ 30, "NOWT", "NoWaitSwitch" },	/* 036B */
	{ 31, "AIRDW", "ReadADChannel" },	/* 037B */
	{ 32, "SPCLO", "CloseSpoolingFile" },	/* 040B */
	{ 33, "ROBJE", "ReadObjectEntry" },	/* 041B */
	{ 35, "CLOSE", "CloseFile" },	/* 043B */
	{ 36, "RUSER", "GetUserEntry" },	/* 044B */
	{ 40, "OPEN", "OpenFile" },	/* 050B */
	{ 42, "TERMO", "TerminalMode" },	/* 052B */
	{ 43, "RSEGM", "GetSegmentEntry" },	/* 053B */
	{ 44, "MDLFI", "DeleteFile" },	/* 054B */
	{ 45, "RSQPE", "GetSpoolingEntry" },	/* 055B */
	{ 46, "PASET", "SetUserParam" },	/* 056B */
	{ 47, "PAGEI", "GetUserParam" },	/* 057B */
	{ 48, "ND500Function", "N500M" },	/* 060B */
	{ 49, "FIXC5", "MemoryAllocation" },	/* 061B */
	{ 50, "RMAX", "GetBytesInFile" },	/* 062B */
	{ 51, "B41NW", "In4x2Bytes" },	/* 063B */
	{ 52, "ERMSG", "WarningMessage" },	/* 064B */
	{ 53, "QERMS", "ErrorMessage" },	/* 065B */
	{ 54, "ISIZE", "InBufferSpace" },	/* 066B */
	{ 55, "OSIZE", "OutBufferSpace" },	/* 067B */
	{ 56, "COMMND", "CallCommand" },	/* 070B */
	{ 57, "DESCF", "DisableEscape" },	/* 071B */
	{ 58, "EESCF", "EnableEscape" },	/* 072B */
	{ 59, "SMAX", "SetMaxBytes" },	/* 073B */
	{ 60, "SETBT", "SetStartByte" },	/* 074B */
	{ 61, "REABT", "GetStartByte" },	/* 075B */
	{ 62, "SETBS", "SetBlockSize" },	/* 076B */
	{ 63, "SETBL", "SetStartBlock" },	/* 077B */
	{ 64, "RT", "StartRTProgram" },	/* 100B */
	{ 65, "SET", "DelayStart" },	/* 101B */
	{ 66, "ABSET", "StartupTime" },	/* 102B */
	{ 67, "INTV", "StartupInterval" },	/* 103B */
	{ 68, "HOLD", "SuspendProgram" },	/* 104B */
	{ 69, "ABORT", "StopRTProgram" },	/* 105B */
	{ 70, "CONCT", "StartOnInterrupt" },	/* 106B */
	{ 71, "DSCNT", "NoInterruptStart" },	/* 107B */
	{ 72, "PRIOR", "SetRTPriority" },	/* 110B */
	{ 73, "UPDAT", "SetClock" },	/* 111B */
	{ 74, "CLADJ", "AdjustClock" },	/* 112B */
	{ 75, "CLOCK", "GetCurrentTime" },	/* 113B */
	{ 76, "TUSED", "GetTimeUsed" },	/* 114B */
	{ 77, "FIX", "FixScattered" },	/* 115B */
	{ 78, "UNFIX", "UnfixSegment" },	/* 116B */
	{ 79, "RFILE", "ReadFromFile" },	/* 117B */
	{ 80, "WFILE", "WriteToFile" },	/* 120B */
	{ 81, "WAITF", "AwaitFileTransfer" },	/* 121B */
	{ 82, "RESRV", "ReserveResource" },	/* 122B */
	{ 83, "RELES", "ReleaseResource" },	/* 123B */
	{ 84, "PRSRV", "ForceReserve" },	/* 124B */
	{ 85, "PRLRS", "ForceRelease" },	/* 125B */
	{ 86, "DSET", "ExactDelayStart" },	/* 126B */
	{ 87, "DABST", "ExactStartup" },	/* 127B */
	{ 88, "DINTV", "ExactInterval" },	/* 130B */
	{ 89, "ABSTR", "DataTransfer" },	/* 131B */
	{ 90, "MCALL", "JumpToSegment" },	/* 132B */
	{ 91, "MEXIT", "ExitFromSegment" },	/* 133B */
	{ 92, "RTEXT", "ExitRTProgram" },	/* 134B */
	{ 93, "RTWT", "WaitForRestart" },	/* 135B */
	{ 94, "RTON", "EnableRTStart" },	/* 136B */
	{ 95, "RTOFF", "DisableRTStart" },	/* 137B */
	{ 96, "WHDEV", "ReservationInfo" },	/* 140B */
	{ 97, "IOSET", "DeviceControl" },	/* 141B */
	{ 98, "ERMON", "ToErrorDevice" },	/* 142B */
	{ 99, "RSIO", "ExecutionInfo" },	/* 143B */
	{ 100, "MAGTP", "DeviceFunction" },	/* 144B */
	{ 102, "IPRIV", "PrivInstruction" },	/* 146B */
	{ 103, "CAMAC", "CAMACFunction" },	/* 147B */
	{ 104, "GL", "CAMACGLRegister" },	/* 150B */
	{ 105, "GRTDA", "GetRTAddress" },	/* 151B */
	{ 106, "GRTNA", "GetRTName" },	/* 152B */
	{ 107, "IOXN", "CAMACIOInstruction" },	/* 153B */
	{ 108, "ASSIG", "AssignCAMACLAM" },	/* 154B */
	{ 109, "GRAPH", "GraphicFunction" },	/* 155B */
	{ 111, "ENTSG", "SegmentToPageTable" },	/* 157B */
	{ 112, "FIXC", "FixContiguous" },	/* 160B */
	{ 113, "INSTR", "InString" },	/* 161B */
	{ 114, "OUTST", "OutString" },	/* 162B */
	{ 116, "WSEG", "SaveSegment" },	/* 164B */
	{ 117, "DIW", "GetInRegisters" },	/* 165B */
	{ 119, "REENT", "AttachSegment" },	/* 167B */
	{ 120, "US0", "UserDef0" },	/* 170B */
	{ 121, "US1", "UserDef1" },	/* 171B */
	{ 122, "US2", "UserDef2" },	/* 172B */
	{ 123, "US3", "UserDef3" },	/* 173B */
	{ 124, "US4", "UserDef4" },	/* 174B */
	{ 125, "US5", "UserDef5" },	/* 175B */
	{ 126, "US6", "UserDef6" },	/* 176B */
	{ 127, "US7", "UserDef7" },	/* 177B */
	{ 128, "XMSG", "XMSGFunction" },	/* 200B */
	{ 129, "MHDLC", "HDLCfunction" },	/* 201B */
	{ 134, "EDTRM", "TerminationHandling" },	/* 206B */
	{ 135, "RERRP", "GetErrorInfo" },	/* 207B */
	{ 138, "SREEN", "ReentrantSegment" },	/* 212B */
	{ 139, "MUIDI", "GetDirUserIndexes" },	/* 213B */
	{ 140, "GUSNA", "GetUserName" },	/* 214B */
	{ 141, "DROBJ", "GetObjectEntry" },	/* 215B */
	{ 142, "DWOBJ", "SetObjectEntry" },	/* 216B */
	{ 143, "GUIOI", "GetAllFileIndexes" },	/* 217B */
	{ 144, "DOPEN", "DirectOpen" },	/* 220B */
	{ 145, "CRALF", "CreateFile" },	/* 221B */
	{ 146, "GBSIZ", "GetAddressArea" },	/* 222B */
	{ 151, "MSDAE", "SetEscLocalChars" },	/* 227B */
	{ 152, "MGDAE", "GetEscLocalChars" },	/* 230B */
	{ 153, "EXPFI", "ExpandFile" },	/* 231B */
	{ 154, "MRNFI", "RenameFile" },	/* 232B */
	{ 155, "STEFI", "SetTemporaryFile" },	/* 233B */
	{ 156, "SPEFI", "SetPeripheralName" },	/* 234B */
	{ 157, "SCROP", "ScratchOpen" },	/* 235B */
	{ 158, "SPERD", "SetPermanentOpen" },	/* 236B */
	{ 159, "SFACC", "SetFileAccess" },	/* 237B */
	{ 160, "APSPE", "AppendSpooling" },	/* 240B */
	{ 161, "SUSCN", "NewUser" },	/* 241B */
	{ 162, "RUSCN", "OldUser" },	/* 242B */
	{ 163, "FDINA", "GetDirNameIndex" },	/* 243B */
	{ 164, "GDIEN", "GetDirEntry" },	/* 244B */
	{ 165, "GNAEN", "GetNameEntry" },	/* 245B */
	{ 166, "REDIR", "ReserveDir" },	/* 246B */
	{ 167, "RLDIR", "ReleaseDir" },	/* 247B */
	{ 168, "FDFDI", "GetDefaultDir" },	/* 250B */
	{ 169, "COPAG", "CopyPage" },	/* 251B */
	{ 170, "BCLOS", "BackupClose" },	/* 252B */
	{ 171, "CRALN", "NewFileVersion" },	/* 253B */
	{ 172, "GERDV", "GetErrorDevice" },	/* 254B */
	{ 173, "PIOCM", "PIOCFunction" },	/* 255B */
	{ 174, "DEABF", "FullFileName" },	/* 256B */
	{ 175, "FOPEN", "OpenFileInfo" },	/* 257B */
	{ 178, "CPUST", "GetSystemInfo" },	/* 262B */
	{ 179, "GDEVT", "GetDeviceType" },	/* 263B */
	{ 183, "TMOUT", "TimeOut" },	/* 267B */
	{ 184, "RDPAG", "ReadDiskPage" },	/* 270B */
	{ 185, "WDPAG", "WriteDiskPage" },	/* 271B */
	{ 186, "DELPG", "DeletePage" },	/* 272B */
	{ 187, "MGFIL", "GetFileName" },	/* 273B */
	{ 188, "FOBJN", "GetFileIndexes" },	/* 274B */
	{ 189, "STRFI", "SetTerminalName" },	/* 275B */
	{ 190, "ELOFU", "EnableLocal" },	/* 276B */
	{ 191, "DLOFU", "DisableLocal" },	/* 277B */
	{ 192, "EUSEL", "SetEscapeHandling" },	/* 300B */
	{ 193, "DUSEL", "StopEscapeHandling" },	/* 301B */
	{ 194, "ELON", "OnEscLocalFunction" },	/* 302B */
	{ 195, "ELOFF", "OffEscLocalFunction" },	/* 303B */
	{ 198, "GTMOD", "GetTerminalMode" },	/* 306B */
	{ 199, "TNOWAI", "TerminalNoWait" },	/* 307B */
	{ 200, "TBIN8", "In8AndFlag" },	/* 310B */
	{ 201, "WDIEN", "WriteDirEntry" },	/* 311B */
	{ 202, "MOINF", "CheckMonCall" },	/* 312B */
	{ 203, "IBRISZ", "InBufferState" },	/* 313B */
	{ 204, "SRUSI", "DefaultRemoteSystem" },	/* 314B */
	{ 205, "MLAMU", "LAMUFunction" },	/* 315B */
	{ 206, "SRLMO", "SetRemoteAccess" },	/* 316B */
	{ 207, "UECOM", "ExecuteCommand" },	/* 317B */
	{ 210, "GSGNO", "GetSegmentNo" },	/* 322B */
	{ 211, "SPLRE", "SegmentOverlay" },	/* 323B */
	{ 212, "OCTIO", "OctobusFunction" },	/* 324B */
	{ 213, "MBECH", "BatchModeEcho" },	/* 325B */
	{ 214, "MLOGI", "LogInStart" },	/* 326B */
	{ 215, "FSMTY", "FileSystemFunction" },	/* 327B */
	{ 216, "TERST", "TerminalStatus" },	/* 330B */
	{ 218, "TREPP", "TerminalLineInfo" },	/* 332B */
	{ 219, "UDMA", "DMAFunction" },	/* 333B */
	{ 220, "GETXM", "GetErrorMessage" },	/* 334B */
	{ 221, "EXABS", "TransferData" },	/* 335B */
	{ 222, "IOMTY", "Terminal" },	/* 336B */
	{ 223, "SPCHG", "ChangeSegment" },	/* 337B */
	{ 224, "RSREC", "ReadSystemRecord" },	/* 340B */
	{ 225, "SGMTY", "SegmentFunction" },	/* 341B */
	{ 256, "MACROE", "ErrorReturn" },	/* 400B */
	{ 257, "DIASS", "DisAssemble" },	/* 401B */
	{ 258, "RFLAG", "GetInputFlags" },	/* 402B */
	{ 259, "WFLAG", "SetOutputFlags" },	/* 403B */
	{ 260, "IOFIX", "FixIOArea" },	/* 404B */
	{ 261, "USTRK", "SwitchUserBreak" },	/* 405B */
	{ 262, "RWRTC", "AccessRTCommon" },	/* 406B */
	{ 264, "FIXMEM", "FixInMemory" },	/* 410B */
	{ 265, "UNFIXM", "MemoryUnfix" },	/* 411B */
	{ 266, "FSCNT", "FileAsSegment" },	/* 412B */
	{ 267, "FSCDNT", "FileNotAsSegment" },	/* 413B */
	{ 268, "BCNAF", "BCNAFCAMAC" },	/* 414B */
	{ 269, "BCNAF1", "BCNAF1CAMAC" },	/* 415B */
	{ 270, "WSEGN", "SaveND500Segment" },	/* 416B */
	{ 271, "MXPISG", "MaxPagesInMemory" },	/* 417B */
	{ 272, "GRBLK", "GetUserRegisters" },	/* 420B */
	{ 273, "GASGM", "GetActiveSegment" },	/* 421B */
	{ 274, "GSWSP", "GetScratchSegment" },	/* 422B */
	{ 275, "CAPCOP", "CopyCapability" },	/* 423B */
	{ 276, "CAPCLE", "ClearCapability" },	/* 424B */
	{ 277, "SPRNAM", "SetProcessName" },	/* 425B */
	{ 278, "GPRNAM", "GetProcessNo" },	/* 426B */
	{ 279, "GPRNME", "GetOwnProcessInfo" },	/* 427B */
	{ 280, "ADR100", "TranslateAddress" },	/* 430B */
	{ 281, "MWAITF", "AwaitTransfer" },	/* 431B */
	{ 285, "PRT", "ForceTrap" },	/* 435B */
	{ 286, "5PASET", "SetND500Param" },	/* 436B */
	{ 287, "5PAGET", "GetND500Param" },	/* 437B */
	{ 288, "AT5SGM", "Attach500Segment" },	/* 440B */
	{ 320, "STARTP", "StartProcess" },	/* 500B */
	{ 321, "STOPPR", "StopProcess" },	/* 501B */
	{ 322, "SWITCHP", "SwitchProcess" },	/* 502B */
	{ 323, "DVINST", "InputString" },	/* 503B */
	{ 324, "DVOUTS", "OutputString" },	/* 504B */
	{ 325, "GERRCOD", "GetTrapReason" },	/* 505B */
	{ 327, "SPRIO", "SetProcessPriority" },	/* 507B */
	{ 332, "5TMOUT", "ND500TimeOut" },	/* 514B */
};

static const int mon_call_count = sizeof(mon_call_table) / sizeof(mon_call_table[0]);

const struct mon_call *
mon_lookup(int num)
{
	int i;

	for (i = 0; i < mon_call_count; i++) {
		if (mon_call_table[i].number == num)
			return &mon_call_table[i];
	}
	return NULL;
}
