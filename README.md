# Win32k mitigation

This project is just a test case to try the new win32k.sys system call filtering mitigation in Windows 8.

The win32k mitigation policy is a per-thread mitigation which, if enabled, denies the thread the right to call most graphics-related system call within `wink32.sys`. There are way too many of them (~1000, compared to the kernel's 400 ones), and most of their implementations is old code, so this mitigation is quite important since it blocks a high-value target for vulnerability researchers. Unfortunately, only Microsoft Edge and Chrome use it as part of their sandbox, because there is no supported way to use it.

# Filtering mechanism

When a thread first calls a graphics syscall, it gets converted to a "GUI thread". This conversion happens once, and so that's where the mitigation ended up being implemented, probably for performance considerations. The problem is, enforcing the mitigation on an existing process leaves room for many threads to already be converted and thus allowed to make arbitrary system calls.

The mitigation can be enabled in one of two ways :
  - calling SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy) with a handle to an existing process. This can only be really effective for that process' child processes, as explained earlier;
  - calling CreateProcess(EXTENDED_STARTUPINFO_PRESENT) with a `PROC_THREAD_ATTRIBUTE_LIST` containing a `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` attribute. This will necessarily affect all the threads.

# Compatibility issues

When enabled, the mitigation only allows startup of small programs compiled with no graphics imports and linked for the Console subsystem.

However, when linked against a graphics library (say, `user32.dll`), `CreateProcess()` returns an error, and a message box shows an unfriendly `0xC0000142` NT status to the user ([STATUS_DLL_INIT_FAILED](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)) :

![Dialog box with status 0xC0000142](https://github.com/mtth-bfft/win32k-mitigation/raw/master/docs/img/start_error_c0000142.png)

A detour in WinDBG shows that, right after it loaded `imm32.dll` (as a dependency of user32.dll), `ntdll!_LdrpInitialize()` called `ntdll!LdrpInitializationFailure()` which, in turn, called `NtRaiseHardError()` with that status code.

Since debugging processes during their startup (when nothing has been initialized yet) is hard, I tried importing all these graphics library at runtime (using `LoadLibrary`) instead of load time (using an import in the PE header). Results are a bit clearer:

```
 [.] Running from Z:\win32k-mitigation.exe
 [.] Child process created: pid 5000
 [.] Child process started successfully
 [+] Child running with filtered Win32k syscalls

 [.] Trying all gdi32full dependencies:
 [!] Unable to load GDI32.dll: code 8
 [!] Unable to load USER32.dll: code 8

 [.] Trying all user32 dependencies:
 [!] Unable to load GDI32.dll: code 8

 [.] Trying all gdi32 dependencies:
 [!] Unable to load api-ms-win-gdi-internal-uap-l1-1-0.dll: code 8

 [+] Child exiting successfully
 [.] Child process exited with code 0x00000000
 [.] All done, return code 0
```

With runtime loading, we can see exactly at which loading step `LoadLibrary()` fails (with a `ERROR_NOT_ENOUGH_MEMORY` code, this time (?)). It seems loading any one of user32.dll or gdi32.dll will fail because of `api-ms-win-gdi-internal-uap-l1-1-0.dll`. This is not an actual DLL name, but an [ApiSet](https://docs.microsoft.com/en-us/windows/desktop/apiindex/windows-apisets), so we have to get back to runtime debugging to sort it out. To be continued... 

# TODO

- Find out whether SetProcessMitigationPolicy() actually enforces the restriction flag on all existing threads, and where
- Find out if there is a way to generically stub win32k system calls at DLL load time
- Automate (e.g. JS WinDBG script) listing filtered/non-filtered Win32k syscalls

# References

- [MSDN documentation on SetProcessMitigationPolicy](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy)
- [MSDN documentation on the system call disable policy](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-process_mitigation_system_call_disable_policy)
- [Win32k System Call Filtering Deep Dive - Morten Schenk](https://improsec.com/tech-blog/win32k-system-call-filtering-deep-dive)
- [The Windows Sandbox Paradox - James Forshaw Nullcon 2015](https://nullcon.net/website/archives/ppt/goa-15/the-windows-sandbox-paradox.pdf)
