#include "CPH_Threads.h"
#if defined _WIN32 || defined _WIN64
#include <windows.h>
const DWORD MS_VC_EXCEPTION = 0x406D1388;

#pragma pack(push,8)
	typedef struct tagTHREADNAME_INFO {
		DWORD dwType; // Must be 0x1000.
		LPCSTR szName; // Pointer to name (in user addr space).
		DWORD dwThreadID; // Thread ID (-1=caller thread).
		DWORD dwFlags; // Reserved for future use, must be zero.
	} THREADNAME_INFO;
#pragma pack(pop)

int pthread_create(pthread_t *thread, void *attr, void *(*start_routine) (void *), void *arg)
{
	*thread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)start_routine, arg, NULL, NULL);
	return thread == NULL ? GetLastError() : ERROR_SUCCESS;
}

void pthread_setname_np(pthread_t thread, char* threadName)
{
	THREADNAME_INFO info;
	info.dwType = 0x1000;
	info.szName = threadName;
	info.dwThreadID = thread;
	info.dwFlags = 0;

	/*__try {
		RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
	} __except (EXCEPTION_EXECUTE_HANDLER) { }*/
}
#endif