#include <sys/types.h>
#include <stdbool.h>
#include "CPH_Threads.h"

pthread_t		checkThread;
pthread_t		harvestThread;
pthread_t		dataThread;
pthread_t		removeThread;

bool Service;
#define SERVICE_NAME "LiveProxies"
#define SERVICE_NAME_DISPLAY "LiveProxies Proxy Checker"

void CheckLoop();
void RemoveThread();
void RequestBase();