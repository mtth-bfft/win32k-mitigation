#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "mem.h"

static BOOL TestLoadLib(PCTSTR swzName)
{
	if (LoadLibrary(swzName) == NULL)
	{
		_tprintf(TEXT(" [!] Unable to load %s: code %u\n"), swzName, GetLastError());
		return FALSE;
	}
	return TRUE;
}

int _tmain(int argc, PCTSTR argv[])
{
	int res = 0;
	HMODULE hSelf = NULL;
	TCHAR swzSelfPath[MAX_PATH + 1] = { 0 };
	PPROC_THREAD_ATTRIBUTE_LIST pAttr = NULL;
	SIZE_T dwBufLen = 0;
	DWORD dwMitigationPolicy = PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;
	STARTUPINFOEX startInfo = { 0 };
	PROCESS_INFORMATION procInfo = { 0 };
	DWORD dwExitCode = 0;
	PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY effectivePolicy = { 0 };

	if (argc >= 1 && _tcsicmp(argv[0], TEXT("self-run")) == 0)
	{
		_tprintf(TEXT(" [.] Child process started successfully\n"));

		if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessSystemCallDisablePolicy, &effectivePolicy, sizeof(effectivePolicy)))
		{
			_tprintf(TEXT(" [!] Could not query system call filter policy in child: code %u\n"), GetLastError());
		}
		else if (!effectivePolicy.DisallowWin32kSystemCalls)
		{
			_tprintf(TEXT(" [!] Child running with no filtering on Win32k syscalls\n"));
		}
		else
		{
			_tprintf(TEXT(" [+] Child running with filtered Win32k syscalls\n"));
		}

		if (LoadLibrary(TEXT("gdi32full.dll")) == NULL)
		{
			_tprintf(TEXT("\n"));
			_tprintf(TEXT(" [.] Trying all gdi32full dependencies:\n"));
			TestLoadLib(TEXT("msvcp_win.dll"));
			TestLoadLib(TEXT("api-ms-win-crt-string-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-crt-runtime-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-crt-private-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-string-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-localization-l1-2-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-heap-l2-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-rtlsupport-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-libraryloader-l1-2-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-sysinfo-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-memory-l1-1-1.dll"));
			TestLoadLib(TEXT("api-ms-win-core-errorhandling-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-processenvironment-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-file-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-handle-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-registry-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-file-l1-2-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-synch-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-heap-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-file-l2-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-memory-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-threadpool-l1-2-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-processthreads-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-debug-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-string-l2-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-security-base-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-processthreads-l1-1-1.dll"));
			TestLoadLib(TEXT("api-ms-win-core-profile-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-interlocked-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-kernel32-legacy-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-heap-obsolete-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-string-obsolete-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-stringansi-l1-1-0.dll"));
			TestLoadLib(TEXT("ntdll.dll"));
			TestLoadLib(TEXT("win32u.dll"));
			TestLoadLib(TEXT("api-ms-win-core-delayload-l1-1-1.dll"));
			TestLoadLib(TEXT("api-ms-win-core-delayload-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-privateprofile-l1-1-0.dll"));
			TestLoadLib(TEXT("api-ms-win-core-localization-private-l1-1-0.dll"));
			TestLoadLib(TEXT("GDI32.dll"));
			TestLoadLib(TEXT("USER32.dll"));
			_tprintf(TEXT("\n"));

			if (LoadLibrary(TEXT("USER32.dll")) == NULL)
			{
				_tprintf(TEXT("\n"));
				_tprintf(TEXT(" [.] Trying all user32 dependencies:\n"));
				TestLoadLib(TEXT("win32u.dll"));
				TestLoadLib(TEXT("ntdll.dll"));
				TestLoadLib(TEXT("api-ms-win-core-localization-l1-2-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-registry-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-heap-l2-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-libraryloader-l1-2-0.dll"));
				TestLoadLib(TEXT("api-ms-win-eventing-provider-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-processthreads-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-synch-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-string-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-sysinfo-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-security-base-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-handle-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-errorhandling-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-string-l2-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-synch-l1-2-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-processenvironment-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-file-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-processthreads-l1-1-1.dll"));
				TestLoadLib(TEXT("api-ms-win-core-memory-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-profile-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-heap-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-memory-l1-1-3.dll"));
				TestLoadLib(TEXT("api-ms-win-core-privateprofile-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-atoms-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-heap-obsolete-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-string-obsolete-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-localization-obsolete-l1-2-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-stringansi-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-sidebyside-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-kernel32-private-l1-1-0.dll"));
				TestLoadLib(TEXT("KERNELBASE.dll"));
				TestLoadLib(TEXT("api-ms-win-core-kernel32-legacy-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-appinit-l1-1-0.dll"));
				TestLoadLib(TEXT("GDI32.dll"));
				TestLoadLib(TEXT("api-ms-win-core-delayload-l1-1-1.dll"));
				TestLoadLib(TEXT("api-ms-win-core-delayload-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-apiquery-l1-1-0.dll"));
				_tprintf(TEXT("\n"));
			}

			if (LoadLibrary(TEXT("GDI32.dll")) == NULL)
			{
				_tprintf(TEXT("\n"));
				_tprintf(TEXT(" [.] Trying all gdi32 dependencies:\n"));
				TestLoadLib(TEXT("ntdll.dll"));
				TestLoadLib(TEXT("api-ms-win-core-heap-l2-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-libraryloader-l1-2-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-processthreads-l1-1-1.dll"));
				TestLoadLib(TEXT("api-ms-win-core-processthreads-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-profile-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-sysinfo-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-errorhandling-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-gdi-internal-uap-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-delayload-l1-1-1.dll"));
				TestLoadLib(TEXT("api-ms-win-core-delayload-l1-1-0.dll"));
				TestLoadLib(TEXT("api-ms-win-core-apiquery-l1-1-0.dll"));
				_tprintf(TEXT("\n"));
			}
		}

		_tprintf(TEXT(" [+] Child exiting successfully\n"));
		ExitProcess(0);
	}

	hSelf = GetModuleHandle(NULL);
	GetModuleFileName(hSelf, swzSelfPath, MAX_PATH);

	_tprintf(TEXT(" [.] Running from %s\n"), swzSelfPath);

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
		_tprintf(TEXT(" [.] Child process exited with code 0x%08X\n"), dwExitCode);
	}

cleanup:
	_tprintf(TEXT(" [.] All done, return code %d\n"), res);
	return res;
}