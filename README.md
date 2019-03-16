# Win32k mitigation

This project is just a test case to try the new win32k.sys system call filtering mitigation in Windows 10.

The win32k mitigation policy is a per-thread mitigation which, if enabled, denies a process the right to call most graphics-related system call within wink32.sys. There are way too many of them (~1000, compared to the kernel's 400 ones), and most of their implementations is old code, making it a target for vulnerability researchers.

The first thing you have to get around when enabling it is that minimal applications (C console applications compiled with msvc and just a `#include <Windows.h>`) won't start anymore. `CreateProcess()` returns an error, and a troubling 0xC0000142 NT status ([STATUS_DLL_INIT_FAILED](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)) is shown to the user in a dialog box:

![Dialog box with status 0xC0000142](https://github.com/mtth-bfft/win32k-mitigation/raw/master/docs/img/start_error_c0000142.png)

To be continued

# TODO

- Find out which system calls exactly are still allowed with this mitigation enforced

# References

- [MSDN documentation on SetProcessMitigationPolicy](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy)
- [MSDN documentation on the system call disable policy](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-process_mitigation_system_call_disable_policy)
- [The Windows Sandbox Paradox - James Forshaw Nullcon 2015](https://nullcon.net/website/archives/ppt/goa-15/the-windows-sandbox-paradox.pdf)
- [Reverse Engineering the Win32k Type Isolation Mitigation - Quarkslab](https://blog.quarkslab.com/reverse-engineering-the-win32k-type-isolation-mitigation.html)
- [Win32k System Call Filtering Deep Dive - Morten Schenk](https://improsec.com/tech-blog/win32k-system-call-filtering-deep-dive)
