#pragma once

// PrintOut
#define MAX_LOG_SIZE 1024
#if defined(_DEBUG)
//MessageBox(NULL, s_PrintOutLogbuf, _T("DudeLoader"), MB_ICONEXCLAMATION);
#define PrintOut(fmt, ...) \
do { \
	static TCHAR s_PrintOutLogbuf[MAX_LOG_SIZE]; \
	if (fmt) { \
		_sntprintf_s(s_PrintOutLogbuf, MAX_LOG_SIZE, fmt, ##__VA_ARGS__); \
		OutputDebugString(s_PrintOutLogbuf); \
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