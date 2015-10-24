#pragma once

#ifdef __linux__
	#include <pthread.h>
#elif defined _WIN32 || defined _WIN64
	#include <windows.h>
	typedef HANDLE pthread_mutex_t;
	typedef HANDLE pthread_t;

	#define pthread_mutex_init(x, a) *x = CreateMutex(NULL, FALSE, NULL)
	#define pthread_mutex_lock(x) WaitForSingleObject(*x, INFINITE);
	#define pthread_mutex_unlock(x) ReleaseMutex(*x);
	#define pthread_mutex_destroy(x) CloseHandle(*x);

	#define pthread_detach(x) CloseHandle(x);
	int pthread_create(pthread_t *thread, void *attr, void *(*start_routine) (void *), void *arg);
	void pthread_setname_np(pthread_t thread, char* threadName);

#endif