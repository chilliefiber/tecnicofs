#include "../fs/operations.h"
#include <assert.h>
#include <string.h>
#include <pthread.h>

#define COUNT 1000 // should be divisible by THREAD_COUNT
#define SIZE 250
#define THREAD_COUNT 10

/**
   This test fills in a new file via multiple writes, 
   where some calls to tfs_write may imply filling in 2 consecutive blocks, 
   then checks if the file contents are as expected.
   It checks this using multiple threads, with the same fd
 */


char *path = "/f1";
char input[SIZE]; 
int fd;
void *read_and_assert() {
    char output [SIZE];

    for (int i = 0; i < COUNT / THREAD_COUNT; i++) {
        assert(tfs_read(fd, output, SIZE) == SIZE);
        assert (memcmp(input, output, SIZE) == 0);
    }

    return NULL;
}

int main() {


    /* Writing this buffer multiple times to a file stored on 1KB blocks will 
       sometimes target 2 consecutive blocks (since 1KB is *not* a multiple of SIZE=250) 
    */
    memset(input, 'A', SIZE);


    assert(tfs_init() != -1);

    /* Write input COUNT times into a new file */
    fd = tfs_open(path, TFS_O_CREAT);
    assert(fd != -1);
    int i;
    for (i = 0; i < COUNT; i++) {
        assert(tfs_write(fd, input, SIZE) == SIZE);
    }
    assert(tfs_close(fd) != -1);

    /* Open again to check if contents are as expected */
    fd = tfs_open(path, 0);
    assert(fd != -1 );
    pthread_t th[THREAD_COUNT];
    int pthread_ret_value;
    for (i = 0; i < THREAD_COUNT; i++) {
        if ((pthread_ret_value = pthread_create(&th[i], NULL, &read_and_assert, NULL)) != 0) {
            fprintf(stderr, "Error creating thread: %s\n", strerror(pthread_ret_value)); 
            return -1;
        }
    }

    for (i = 0; i < THREAD_COUNT; i++) {
        if ((pthread_ret_value = pthread_join(th[i], NULL)) != 0) {
            fprintf(stderr, "Error joining thread: %s\n", strerror(pthread_ret_value)); 
            return -1;
        }
    }

    assert(tfs_close(fd) != -1);
    printf("Sucessful test\n");

    return 0;
}
