#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "mem.h"

int _tmain(int argc, PCTSTR argv[])
{
	int res = 0;
	HWINSTA hWinsta = NULL;
	HMODULE hSelf = NULL;
	TCHAR swzSelfPath[MAX_PATH + 1] = { 0 };
	HMODULE hWin32u = NULL;
	PVOID pNtUserSetImeInfoEx = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST pAttr = NULL;
	SIZE_T dwBufLen = 0;
	DWORD dwMitigationPolicy = PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;
	STARTUPINFOEX startInfo = { 0 };
	PROCESS_INFORMATION procInfo = { 0 };
	DWORD dwExitCode = 0;

	if (argc >= 1 && _tcsicmp(argv[0], TEXT("self-run")) == 0)
	{
		_tprintf(TEXT(" [.] Child process started successfully\n"));
		ExitProcess(0);
	}

	hSelf = GetModuleHandle(NULL);
	GetModuleFileName(hSelf, swzSelfPath, MAX_PATH);

	_tprintf(TEXT(" [.] Running from %s\n"), swzSelfPath);

	hWinsta = GetProcessWindowStation();
	if (hWinsta == NULL)
	{
		res = GetLastError();
		_ftprintf(stderr, TEXT("Error: unable to acquire handle to our own window station, code %u\n"), res);
		goto cleanup;
	}
	_tprintf(TEXT(" [.] Window station handle: %p\n"), (PVOID)hWinsta);

	hWin32u = LoadLibrary(TEXT("win32u.dll"));
	if (hWin32u == NULL)
	{
		res = GetLastError();
		_ftprintf(stderr, TEXT("Error: unable to load win32u.dll, code %u\n"), res);
		goto cleanup;
	}

	pNtUserSetImeInfoEx = (PVOID)GetProcAddress(hWin32u, "NtUserSetImeInfoEx");
	if (pNtUserSetImeInfoEx == NULL)
	{
		res = GetLastError();
		_ftprintf(stderr, TEXT("Error: unable to locate NtUserSetImeInfoEx(), code %u\n"), res);
		goto cleanup;
	}
	_tprintf(TEXT(" [.] NtUserSetImeInfoEx() is at %p\n"), pNtUserSetImeInfoEx);

	if (InitializeProcThreadAttributeList(NULL, 1, 0, &dwBufLen) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		res = GetLastError();
		_ftprintf(stderr, TEXT("Error: unable to get InitializeProcThreadAttributeList()'s required buffer length, code %u\n"), res);
		goto cleanup;
	}
	pAttr = (PPROC_THREAD_ATTRIBUTE_LIST)safe_alloc(dwBufLen);
	if (!InitializeProcThreadAttributeList(pAttr, 1, 0, &dwBufLen))
	{
		res = GetLastError();
		_ftprintf(stderr, TEXT("Error: InitializeProcThreadAttributeList() failed with code %d\n"), res);
		goto cleanup;
	}
	if (!UpdateProcThreadAttribute(pAttr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwMitigationPolicy, sizeof(dwMitigationPolicy), NULL, NULL))
	{
		res = GetLastError();
		_ftprintf(stderr, TEXT("Error: UpdateProcThreadAttribute() failed with code %d\n"), res);
		goto cleanup;
	}

	ZeroMemory(&startInfo, sizeof(startInfo));
	ZeroMemory(&procInfo, sizeof(procInfo));
	startInfo.lpAttributeList = pAttr;
	startInfo.StartupInfo.cb = sizeof(startInfo);

	if (!CreateProcess(swzSelfPath, TEXT("self-run"), NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFO*)&startInfo, &procInfo))
	{
		res = GetLastError();
		_ftprintf(stderr, TEXT("Error: CreateProcess() failed with code %d\n"), res);
		goto cleanup;
	}

	_tprintf(TEXT(" [.] Child process created: pid %u\n"), procInfo.dwProcessId);

	WaitForSingleObject(procInfo.hProcess, INFINITE);

	if (!GetExitCodeProcess(procInfo.hProcess, &dwExitCode))
	{
		res = GetLastError();
		_ftprintf(stderr, TEXT("Error: GetExitCodeProcess() failed with code %d\n"), res);
	}
	else
	{
		_tprintf(TEXT(" [.] Child process exited with code %u\n"), dwExitCode);
	}

cleanup:
	_tprintf(TEXT(" [.] All done, return code %d\n"), res);
	return res;
}