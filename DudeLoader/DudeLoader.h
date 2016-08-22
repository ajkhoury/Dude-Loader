#pragma once

#include <Windows.h>
#include <Winternl.h>

#include <io.h>
#include <stdio.h>
#include <tchar.h>

__inline bool FileExists(const TCHAR* filepath)
{ 
	if (_taccess(filepath, 0x00) != -1) {
		return true;
	}
	return false;
}

// PrintOut
#define MAX_LOG_SIZE 1024
#if defined(_DEBUG)
#define PrintOut(fmt, ...) \
do { \
	static TCHAR s_PrintOutLogbuf[MAX_LOG_SIZE]; \
	if (fmt) { \
		_sntprintf_s(s_PrintOutLogbuf, MAX_LOG_SIZE, fmt, ##__VA_ARGS__); \
		OutputDebugString(s_PrintOutLogbuf); \
		MessageBox(NULL, s_PrintOutLogbuf, _T("DudeLoader"), MB_ICONEXCLAMATION); \
	} \
} while (0);
#else
#define PrintOut(fmt, ...) \
do { \
	static TCHAR s_PrintOutLogbuf[MAX_LOG_SIZE]; \
	if (fmt) { \
		_sntprintf_s(s_PrintOutLogbuf, MAX_LOG_SIZE, fmt, ##__VA_ARGS__); \
		OutputDebugString(s_PrintOutLogbuf); \
	} \
} while (0);
#endif