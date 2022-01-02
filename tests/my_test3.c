#include "../fs/operations.h"
#include <assert.h>
#include <string.h>
#include <pthread.h>
#define COUNT 1000 
#define SIZE 250
#define THREAD_COUNT 11

/**
   This test fills in a new file via multiple writes, 
   where some calls to tfs_write may imply filling in 2 consecutive blocks, 
   then checks with multiple threads with different fds if the file contents are as expected. While checking, there is a single thread
   also writing (appending) to the file. It then joins the write thread, and
   uses the previous read threads and their respective file descriptors to read what the write thread wrote.
   Note: Make sure that you don't write more bytes than fit in a file. You'll write SIZE*COUNT*2 bytes
 */


char *path = "/f1";
char input[SIZE]; 
int fds[THREAD_COUNT - 1];

void *read_and_open(void *arg) {
    char output [SIZE];
    int *fd = (int *) arg;
    /* Open again to check if contents are as expected */
    *fd = tfs_open(path, 0);
    assert(*fd != -1 );
    for (int i = 0; i < COUNT; i++) {
        assert(tfs_read(*fd, output, SIZE) == SIZE);
        assert (memcmp(input, output, SIZE) == 0);
    }
    return NULL;
}

void *read_and_close(void *arg) {
    int *fd = (int *) arg;
    assert(fd != NULL);
    char output [SIZE];
    for (int i = 0; i < COUNT; i++) {
        assert(tfs_read(*fd, output, SIZE) == SIZE);
        assert (memcmp(input, output, SIZE) == 0);
    }
    assert(tfs_close(*fd) != -1);
    return NULL;
}

void *write_and_assert() {
    /* Write input COUNT times into a new file */
    int fd = tfs_open(path, TFS_O_APPEND);
    assert(fd != -1);
    for (int i = 0; i < COUNT; i++) {
        assert(tfs_write(fd, input, SIZE) == SIZE);
    }
    assert(tfs_close(fd) != -1);
    return NULL;
}

int main() {


    /* Writing this buffer multiple times to a file stored on 1KB blocks will 
       sometimes target 2 consecutive blocks (since 1KB is *not* a multiple of SIZE=250) 
    */
    memset(input, 'A', SIZE);


    assert(tfs_init() != -1);

    /* Write input COUNT times into a new file */
    int fd = tfs_open(path, TFS_O_CREAT);
    assert(fd != -1);
    for (int i = 0; i < COUNT; i++) {
        assert(tfs_write(fd, input, SIZE) == SIZE);
    }
    assert(tfs_close(fd) != -1);

    pthread_t th[THREAD_COUNT];
    int pthread_ret_value;
    for (i = 0; i < THREAD_COUNT; i++) {
        if (i < THREAD_COUNT - 1 && (pthread_ret_value = pthread_create(&th[i], NULL, &read_and_open, (void*) &fds[i])) != 0) {
                fprintf(stderr, "Error creating thread: %s\n", strerror(pthread_ret_value)); 
                return -1;
        }
        else if ((pthread_ret_value = pthread_create(&th[i], NULL, &write_and_assert, NULL)) != 0) {
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
    for (i = 0; i < THREAD_COUNT - 1; i++) {
        if ((pthread_ret_value = pthread_create(&th[i], NULL, &read_and_close, (void*) &fds[i])) != 0) {
            fprintf(stderr, "Error creating thread: %s\n", strerror(pthread_ret_value)); 
            return -1;
        }
    }
    for (i = 0; i < THREAD_COUNT - 1; i++) {
        if ((pthread_ret_value = pthread_join(th[i], NULL)) != 0) {
            fprintf(stderr, "Error joining thread: %s\n", strerror(pthread_ret_value)); 
            return -1;
        }
    }
    printf("Sucessful test\n");

    return 0;
}
