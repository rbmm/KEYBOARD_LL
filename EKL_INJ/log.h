#pragma once

#define LOG(...)  CLogFile::s_logfile.__VA_ARGS__

#define DbgPrint CLogFile::s_logfile.printf

#pragma message("=========log")

class CLogFile
{
private:
	HANDLE hFile = 0;

public:
	/*inline */static CLogFile s_logfile;

	void Destroy() 
	{
		if (hFile) CloseHandle(hFile);
	}

	void Init();

	void __cdecl printf(PCSTR format, ...);

	void write(LPCVOID data, DWORD cb)
	{
		if (hFile) WriteFile(hFile, const_cast<void*>(data), cb, &cb, 0);
	}
};

PSECURITY_ATTRIBUTES getSA();
