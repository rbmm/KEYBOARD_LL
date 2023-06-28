#include "stdafx.h"
#include "log.h"

_NT_BEGIN

void DoInject(HANDLE hProcess, PWSTR lpLibFileName, SIZE_T cb)
{
	if (PVOID buf = VirtualAllocEx(hProcess, 0, cb, MEM_COMMIT, PAGE_READWRITE))
	{
		if (0 <= ZwWriteVirtualMemory(hProcess, buf, lpLibFileName, cb, &cb))
		{
			HANDLE hThread;
			if (0 <= RtlCreateUserThread(hProcess, 0, TRUE, 0, 0, 0, (PTHREAD_START_ROUTINE)RtlExitUserThread, 0, &hThread, 0))
			{
				if (0 <= ZwQueueApcThread(hThread, (PKNORMAL_ROUTINE)LoadLibraryExW, buf, 0, 0))
				{
					ZwQueueApcThread(hThread, (PKNORMAL_ROUTINE)VirtualFree, buf, 0, (PVOID)MEM_RELEASE);
					buf = 0;
				}
				ZwResumeThread(hThread, 0);
				NtClose(hThread);
			}
		}
		if (buf) VirtualFreeEx(hProcess, buf, 0, MEM_RELEASE);
	}
}

BOOL IsHighIntegrity(HANDLE hProcess)
{
	BOOL f = FALSE;

	HANDLE hToken;
	if (0 <= ZwOpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		union {
			TOKEN_MANDATORY_LABEL tml;
			UCHAR bb[sizeof(TOKEN_MANDATORY_LABEL) + sizeof(SID)];
		};

		ULONG cb;
		if (0 <= NtQueryInformationToken(hToken, TokenIntegrityLevel, bb, sizeof(bb), &cb))
		{
			if (1 == *RtlSubAuthorityCountSid(tml.Label.Sid))
			{
				f = SECURITY_MANDATORY_HIGH_RID <= *RtlSubAuthoritySid(tml.Label.Sid, 0);
			}
		}
	}

	return f;
}

void InjectAll(BOOL fToAll, PWSTR lpLibFileName, SIZE_T cbLibFileName)
{
	BOOLEAN b;
	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &b);

	ULONG cb = 0x10000;

	NTSTATUS status;
	do 
	{
		status = STATUS_NO_MEMORY;

		if (PVOID buf = new UCHAR[cb += 0x1000])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };
				ULONG SessionId, ProcessId = GetCurrentProcessId();
				ProcessIdToSessionId(GetCurrentProcessId(), &SessionId);
				PSYSTEM_PROCESS_INFORMATION pspi = (PSYSTEM_PROCESS_INFORMATION)buf;
				ULONG NextEntryOffset = 0;
				do 
				{
					(ULONG_PTR&)pspi += NextEntryOffset;

					CLIENT_ID cid = { pspi->UniqueProcessId };

					if (cid.UniqueProcess && pspi->SessionId == SessionId && (ULONG)(ULONG_PTR)cid.UniqueProcess != ProcessId)
					{
						HANDLE hProcess;
						if (0 <= NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &zoa, &cid))
						{
							PROCESS_EXTENDED_BASIC_INFORMATION ebi;
							if (0 <= NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ebi, sizeof(ebi), 0) &&
#ifdef _WIN64
								!
#endif
								ebi.IsWow64Process &&
								!ebi.IsFrozen &&
								!ebi.IsStronglyNamed &&
								(fToAll || IsHighIntegrity(hProcess)))
							{
								DbgPrint("\t>> %x %wZ\r\n", cid.UniqueProcess, &pspi->ImageName);
								DoInject(hProcess, lpLibFileName, cbLibFileName);
							}

							NtClose(hProcess);
						}
					}

				} while (NextEntryOffset = pspi->NextEntryOffset);
			}

			delete [] buf;
		}
	} while (STATUS_INFO_LENGTH_MISMATCH == status);
}

#ifdef _WIN64
#define SF L"64"
#else
#define SF L"32"
#endif

LRESULT CALLBACK hp(int code, WPARAM wParam, LPARAM lParam)
{
	return CallNextHookEx(0, code, wParam, lParam);
}

void WINAPI ep(HANDLE /*hThread*/)
{
	if (wcschr(GetCommandLine(), '?'))
	{
		if (HHOOK hhk = SetWindowsHookExW(WH_KEYBOARD_LL, hp, 0, 0))
		{
			MessageBoxW(0,0,SF,MB_ICONWARNING);
			UnhookWindowsHookEx(hhk);
		}
		ExitProcess(0);
	}

	LOG(Init());

	if (HANDLE hEvent = CreateEventW(getSA(), TRUE, FALSE, L"Global\\***EKL" SF))
	{
		if (GetLastError() == NOERROR)
		{
			if (PWSTR psz = new WCHAR[0x8000])
			{
				if (ULONG cch = GetFullPathNameW(L"EKL.DLL", 0x8000, psz, 0))
				{
					if (INVALID_FILE_ATTRIBUTES == GetFileAttributesW(psz))
					{
						MessageBoxW(0, psz, 0, MB_ICONHAND);
					}
					else
					{
						InjectAll(wcschr(GetCommandLine(), '*') != 0, psz, (1 + cch) * sizeof(WCHAR));

						MessageBoxW(0, L"Hook Active", SF, MB_ICONINFORMATION);
					}
				}
				delete[] psz;
			}
		}
		SetEvent(hEvent);
		NtClose(hEvent);
	}

	LOG(Destroy());
	ExitProcess(0);
}

_NT_END