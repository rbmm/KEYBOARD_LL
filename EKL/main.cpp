#include "stdafx.h"
#include "log.h"
//#define _PRINT_CPP_NAMES_
#include "../inc/asmfunc.h"

EXTERN_C extern IMAGE_DOS_HEADER __ImageBase;

#define RtlPointerToOffset(B,P) ((ULONG)( ((PCHAR)(P)) - ((PCHAR)(B)) ))

struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	struct _PEB_LDR_DATA* Ldr;
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
		ULONG EnvironmentUpdateCount;
	};
	union
	{
		PVOID* KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	//...
};

EXTERN_C
NTSYSAPI
PEB* 
NTAPI 
RtlGetCurrentPeb();

struct KHS {
	ULONG_PTR nCode;
	WPARAM wParam;
	LRESULT (CALLBACK * KeyboardProc)(int , WPARAM , LPARAM);
	LRESULT (CALLBACK * DispatchHook)(int , WPARAM , LPARAM, LRESULT (CALLBACK * )(int , WPARAM , LPARAM));
	KBDLLHOOKSTRUCT hk;
};

#define I__fnHkINLPKBDLLHOOKSTRUCT 0x2D

EXTERN_C
DECLSPEC_IMPORT
LRESULT
CALLBACK
__fnHkINLPKBDLLHOOKSTRUCT(KHS* param);

EXTERN_C PVOID __imp___fnHkINLPKBDLLHOOKSTRUCT = 0;

KHS* __fastcall log__fnHkINLPKBDLLHOOKSTRUCT(KHS* param)
{
	CPP_FUNCTION;

	static LONG _S_n;

	LONG n = InterlockedIncrement(&_S_n);

	DbgPrint("[%x]> %x:%x %p > ( %x-%u-%x %x:%x:%x )\r\n", 
		n, GetCurrentProcessId(), GetCurrentThreadId(), param->KeyboardProc, 
		param->nCode, param->hk.time, param->hk.flags, 
		param->wParam, param->hk.vkCode, param->hk.scanCode);

	HMODULE hmod;
	if (RtlPcToFileHeader(param->KeyboardProc, (void**)&hmod))
	{
		struct MN  
		{
			char sz[0x8040];
			WCHAR wz[0x8000];
		};

		BOOL fOk = FALSE;

		if (MN* p = new MN)
		{
			if (ULONG cch = GetModuleFileNameW(hmod, p->wz, _countof(p->wz)))
			{
				if (NOERROR == GetLastError())
				{
					int len = sprintf_s(p->sz, _countof(p->sz), "[%x]> \"", n);
					if (0 < len)
					{
						if (cch = WideCharToMultiByte(CP_UTF8, 0, p->wz, cch, p->sz + len, _countof(p->sz) - len, 0, 0))
						{
							cch += len;
							if (0 < (len = sprintf_s(p->sz + cch, _countof(p->sz) - cch, "\" + %x\r\n",
								RtlPointerToOffset(hmod, param->KeyboardProc))))
							{
								LOG(write(p->sz, cch + len));
								fOk = TRUE;
							}
						}
					}
				}
			}

			delete p;
		}

		if (!fOk)
		{
			DbgPrint("[%x]> %p + %x\r\n", n, hmod, RtlPointerToOffset(hmod, param->KeyboardProc));
		}
	}

	return param;
}

LRESULT
CALLBACK
hook__fnHkINLPKBDLLHOOKSTRUCT(KHS* param)ASM_FUNCTION;

ULONG SetHook(void** ppv, void* pv)
{
	ULONG op;
	if (VirtualProtect(ppv, sizeof(void*), PAGE_READWRITE, &op))
	{
		*ppv = pv;
		VirtualProtect(ppv, sizeof(void*), op, &op);

		return NOERROR;
	}

	return GetLastError();
}

ULONG SetHook(void** KernelCallbackTable)
{
	void** ppv = &KernelCallbackTable[I__fnHkINLPKBDLLHOOKSTRUCT];

	__imp___fnHkINLPKBDLLHOOKSTRUCT = *ppv;

	if (ULONG dwError = SetHook(ppv, hook__fnHkINLPKBDLLHOOKSTRUCT))
	{
		return dwError;
	}

	return NOERROR;
}

#ifdef _WIN64
#define SF L"64"
#else
#define SF L"32"
#endif

ULONG WINAPI MyEp(HANDLE hEvent)
{
	if (hEvent = OpenEvent(SYNCHRONIZE, FALSE, L"Global\\***EKL" SF))
	{
		HMODULE hmod;
		if (GetModuleHandleExW(0, L"user32.dll", &hmod))
		{
			if (void** KernelCallbackTable = RtlGetCurrentPeb()->KernelCallbackTable)
			{
				if (NOERROR == SetHook(KernelCallbackTable))
				{
					WaitForSingleObject(hEvent, INFINITE);

					if (SetHook(&KernelCallbackTable[I__fnHkINLPKBDLLHOOKSTRUCT], __imp___fnHkINLPKBDLLHOOKSTRUCT))
					{
						__debugbreak();
					}

					Sleep(1000);
				}
			}

			FreeLibrary(hmod);
		}

		CloseHandle(hEvent);
	}

	FreeLibraryAndExitThread((HMODULE)&__ImageBase, 0);
}

BOOLEAN WINAPI DllMain( HMODULE hmod, DWORD ul_reason_for_call, PVOID p)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		//if (IsDebuggerPresent()) __debugbreak();
		DisableThreadLibraryCalls(hmod);
		LOG(Init());
		DbgPrint("ATTACH:%x %S\r\n", GetCurrentProcessId(), GetCommandLineW());
		CloseHandle(CreateThread(0, 0, MyEp, 0, 0, 0));
		break;

	case DLL_PROCESS_DETACH:
		DbgPrint("DETACH:%x %p\r\n", GetCurrentProcessId(), p);
		LOG(Destroy());
		break;
	}

	return TRUE;
}