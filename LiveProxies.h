#include <sys/types.h>
#include "CPH_Threads.h"

pthread_t		checkThread;
pthread_t		harvestThread;
pthread_t		dataThread;
pthread_t		removeThread;

void CheckLoop();
//void DataThread();
void RemoveThread();
void RequestBase();