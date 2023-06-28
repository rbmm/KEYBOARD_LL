#include "stdafx.h"

#include "log.h"

#ifdef _malloca
#undef _malloca
#endif

#ifdef _freea
#undef _freea
#endif

__declspec(noalias) __inline void __cdecl __freea(PVOID pv)
{
	PNT_TIB tib = (PNT_TIB)NtCurrentTeb();
	if (pv < tib->StackLimit || tib->StackBase <= pv) LocalFree(pv);
}

#define _malloca(size) ((size) < 0x1000 ? alloca(size) : LocalAlloc(0, size))
#define _freea(p) __freea(p)

CLogFile CLogFile::s_logfile;

PSECURITY_ATTRIBUTES getSA()
{
	static const SECURITY_DESCRIPTOR sd = { SECURITY_DESCRIPTOR_REVISION, 0, SE_DACL_PRESENT | SE_DACL_PROTECTED };
	static const SECURITY_ATTRIBUTES sa = { sizeof(sa), const_cast<SECURITY_DESCRIPTOR*>(&sd) };

	return const_cast<PSECURITY_ATTRIBUTES>(&sa);
}

void CLogFile::Init()
{
	hFile = CreateFileW(L"\\\\?\\global\\globalroot\\systemroot\\temp\\EKL.log", FILE_APPEND_DATA, 
		FILE_SHARE_READ|FILE_SHARE_WRITE, getSA(), OPEN_ALWAYS, 0, 0);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		hFile = 0;
	}
}

void CLogFile::printf(PCSTR format, ...)
{
	if (!hFile) return ;

	va_list args;
	va_start(args, format);

	PSTR buf = 0;
	int len = 0;
	while (0 < (len = _vsnprintf(buf, len, format, args)))
	{
		if (buf)
		{
			WriteFile(hFile, buf, len, 0, 0);
			break;
		}

		if (!(buf = (PSTR)_malloca(len)))
		{
			break;
		}
	}

	if (buf)
	{
		_freea(buf);
	}
	va_end(args);
}