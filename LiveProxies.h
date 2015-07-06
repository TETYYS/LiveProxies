#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/unistd.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <sys/time.h>

#include <pthread.h>
#include <semaphore.h>
#include <dirent.h>
#include <sys/prctl.h>

pthread_t		checkThread;
pthread_t		harvestThread;
pthread_t		dataThread;
pthread_t		removeThread;

void CheckLoop();
//void DataThread();
void RemoveThread();
void RequestBase();

void MainLoops(bool UVLoop);