#include <stdio.h>
#include <stdint.h> //uint_t
#include <string.h> //strlen, strcat, strncpy
#include <Windows.h> //ShellExecute, GetFullPathName

/*
	References:
	Signatures in PE header compare: https://reverseengineering.stackexchange.com/questions/8217/ways-to-define-portable-executable-bitness-64-vs-32
	Parse PE format practically: https://stackoverflow.com/a/9783522/9182265
*/

// Define PE Formats structs
typedef enum _pe_arch {
	PE_UNKNOWN = 0x0000,
	PE_ANYCPU  = 0x0001,
	PE_x86	  = 0x010B,
	PE_x64	  = 0x020B
} PE_ARCHITECTURE;


// Define ELF Formats structs
typedef enum _elf_arch {
	ELF_UNKNOWN = 0x00,
	ELF_x86 = 0x01,
	ELF_x64 = 0x02
} ELF_ARCHITECTURE;


// Determine the PE file is either 32 or 64 bits
PE_ARCHITECTURE _peArch(FILE *PEFile) {
	//Check the MZ Signature
	uint16_t MZSig;
	fread(&MZSig, sizeof(uint16_t), 1, PEFile);
	if (MZSig != 0x5A4D) //"MZ"
		return PE_UNKNOWN;

	//Jump from MZ to AddressOfNewExeHeader
	fseek(PEFile, 0x3A, SEEK_CUR);
	uint32_t AddressOfNewExeHeader;
	fread(&AddressOfNewExeHeader, sizeof(uint32_t), 1, PEFile);

	//Jump from AddressOfNewExeHeader to PE Signature
	fseek(PEFile, AddressOfNewExeHeader, SEEK_SET);

	//Check the PE Signature
	uint32_t PESig;
	fread(&PESig, sizeof(uint32_t), 1, PEFile);
	if (PESig != 0x004550) //"PE\0\0"
		return PE_UNKNOWN;

	//Jump from PE to MAGIC Signature
	fseek(PEFile, 20, SEEK_CUR);

	//Read the MAGIC Signature
	uint16_t MAGICSig = 0;
	fread(&MAGICSig, sizeof(uint16_t), 1, PEFile);
	return (PE_ARCHITECTURE)MAGICSig;
}


ELF_ARCHITECTURE _elfArch(FILE *ELFFile) {
	//Check the ELF Signature
	uint32_t ELFSig;
	fread(&ELFSig, sizeof(uint32_t), 1, ELFFile);
	if (ELFSig != 0x464C457F) //.ELF
		return ELF_UNKNOWN;

	//Read the CLASS Signature
	char CLASSSig = 0;
	fread(&CLASSSig, sizeof(char), 1, ELFFile);
	return (ELF_ARCHITECTURE)CLASSSig;
}


// Determine Executable Format
int detectArch(FILE *execFile) {
	PE_ARCHITECTURE PEFormat = _peArch(execFile);
	ELF_ARCHITECTURE ELFFormat;
	switch (PEFormat) {
		case PE_UNKNOWN:
			fseek(execFile, 0, SEEK_SET);
			ELFFormat = _elfArch(execFile);
			switch (ELFFormat) {
				case ELF_UNKNOWN:
					return 0;
				case ELF_x86:
					return 1;
				case ELF_x64:
					return 2;
			}
			return 0;
		case PE_ANYCPU:
			return 1;
		case PE_x86:
			return 1;
		case PE_x64:
			return 2;
	}
	return -1;
}


// Parse the working directory of fullpath
void _workingDir(char *filePath, int lenth, char *workingDir) {
	int start = 0;
	for (int i = lenth - 1; i >= 0; --i) {
		if (!start) {
			if (filePath[i] == '\\') {
				start = 1;
				workingDir[i + 1] = '\0';
			} else {
				continue;
			}
		}
		workingDir[i] = filePath[i];
	}
	if (!start)
		workingDir[0] = '\0';
}


// Launcher
void launch(char *loader, char *parameter, char *execFile, char isAdmin, char isMinimized) {
	int para_len = strlen(parameter);

	//Resolve relative paths to absolute paths
	char execFile_fullPath[MAX_PATH];
	DWORD exec_len = GetFullPathName(
		TEXT(execFile),
		MAX_PATH,
		execFile_fullPath,
		NULL
	);

	char loader_fullpath[MAX_PATH];
	DWORD loader_len = GetFullPathName(
		TEXT(loader),
		MAX_PATH,
		loader_fullpath,
		NULL
	);

	//Get the working directory of the launcher
	char workingDir[(int) loader_len + 1];
	_workingDir(loader_fullpath, (int) loader_len, workingDir);

	//Combine the target with launcher options
	int loaderPara_len = para_len + (int) exec_len + 3; //-o "xxx"
	char loaderParameter[loaderPara_len + 1];
	strncpy(loaderParameter, parameter, para_len + 1); //-o
	if (para_len > 0)
		strcat(loaderParameter, " "); //-o (space)
	strcat(loaderParameter, "\""); //-o "
	strcat(loaderParameter, execFile_fullPath); //-o "xxx
	strcat(loaderParameter, "\""); //-o "xxx"

	int returnCode = (int) ShellExecute(
		NULL,
		(isAdmin == '1') ? "runas" : "open",
		loader_fullpath,
		loaderParameter,
		workingDir,
		(isMinimized == '1') ? SW_SHOWMINIMIZED : SW_SHOWNORMAL
	);

	//Error handling
	if (returnCode <= 32) {
		printf("Launch Failed (Error %i)\n", returnCode);
		printf(
			"[%s]\n"
			"[%s]\n"
			"[%s]\n",
			loader_fullpath,
			loaderParameter,
			workingDir
		);	
	}
}


// Auto launch specified PE loaders (debuggers or decompilers) with specified PE file, depending on the given PE file is whether 32 or 64 bits
int main(int argc, char *argv[]) {
	if (argc < 6) {
		printf("Usage: MagicLoader.exe <32 Bits Loader> <64 Bits Loader> <Loader Parameters> <Executable Image File> <Admin Rights> <Minimized>\n");
		return -1;
	}

	// Detect the arch of PE
	FILE *execFile = fopen(argv[4], "rb");
	if (!execFile) {
		printf("Can't open file.\n");
		return -1;
	}
	int format = detectArch(execFile);
	fclose(execFile);

	// Launch the loader
	switch (format) {
		case 1:
			printf("32 Bits\n");
			launch(
				argv[1],	 //32 Bits Loader
				argv[3],	 //Loader Parameters
				argv[4],	 //Executable File
				argv[5][0],  //Admin Rights
				argv[6][0]   //Minimized
			);
			break;
		case 2:
			printf("64 Bits\n");
			launch(
				argv[2],	 //64 Bits Loader
				argv[3],	 //Loader Parameters
				argv[4],	 //Executable File
				argv[5][0], //Admin Rights
				argv[6][0]  //Minimized
			);
			break;
		default:
			printf("Not a valid executable file (PE/ ELF)\n");
	}
	
	return 0;
}