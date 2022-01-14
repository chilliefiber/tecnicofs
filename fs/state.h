#ifndef STATE_H
#define STATE_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdbool.h>

/*
 * Directory entry
 */
typedef struct {
    char d_name[MAX_FILE_NAME];
    int d_inumber;
} dir_entry_t;

typedef enum { T_FILE, T_DIRECTORY } inode_type;

/*
 * I-node
 */
typedef struct {
    inode_type i_node_type;
    size_t i_size;
    int i_data_blocks[INODE_DIRECT_REFERENCES];
    int i_indirect_data_block; // referência para 1 bloco indireto
    pthread_rwlock_t i_rwlock;
    /* in a real FS, more fields would exist here */
} inode_t;

typedef enum { FREE = 0, TAKEN = 1 } allocation_state_t;

/*
 * Open file entry (in open file table)
 */
typedef struct {
    int of_inumber;
    size_t of_offset;
    bool of_append;     
    pthread_mutex_t of_mutex;
} open_file_entry_t;

#define MAX_DIR_ENTRIES (BLOCK_SIZE / sizeof(dir_entry_t)) 


#define MAX_INDIRECT_BLOCKS (BLOCK_SIZE / sizeof(int))

#define MAX_FILE_SIZE (BLOCK_SIZE * (INODE_DIRECT_REFERENCES + MAX_INDIRECT_BLOCKS))  

int state_init();
int state_destroy();

int inode_create(inode_type n_type);
int inode_delete(int inumber);
int inode_clear_file_contents(inode_t *inode);
inode_t *inode_get(int inumber);
int inode_dump(inode_t *inode, FILE *dest_file);
ssize_t inode_write(inode_t *inode, void const *buffer, size_t to_write, size_t file_offset, bool append);
ssize_t inode_read(inode_t *inode, void *buffer, size_t to_read, size_t file_offset, bool append);

int clear_dir_entry(int inumber, int sub_inumber);
int add_dir_entry(int inumber, int sub_inumber, char const *sub_name);
int find_in_dir(int inumber, char const *sub_name);

int data_block_alloc();
int data_block_free(int block_number);
void *data_block_get(int block_number);

open_file_entry_t *add_to_open_file_table(int *fhandle);
int remove_from_open_file_table(int fhandle);
open_file_entry_t *get_open_file_entry(int fhandle);

#endif // STATE_H
