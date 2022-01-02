#ifndef STATE_H
#define STATE_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

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
    /* in a real FS, more fields would exist here */
} inode_t;

typedef enum { FREE = 0, TAKEN = 1 } allocation_state_t;

/*
 * Open file entry (in open file table)
 */
typedef struct {
    int of_inumber;
    size_t of_offset;
} open_file_entry_t;

#define MAX_DIR_ENTRIES (BLOCK_SIZE / sizeof(dir_entry_t)) // só existe 1 diretório, o root. Esse diretório só tem 1 bloco.
                                                           // MAX_DIR_ENTRIES representa o máximo de entradas (ficheiros ou subdiretórios)
// que um diretório guarda. Um diretório tem 1 bloco para armazenar informação sobre os seus ficheiros/subdiretórios, e cada entrada é do tipo dir_entry_t


// the thought process is that the indirect block can be interpreted as an array of indexes to blocks in 
// the arrays fs_data and free_blocks. The functions, written by the professors (data_block_free etc) 
// use an int as an index to these arrays. As such, the indirect block can contain MAX_INDIRECT_BLOCKS
// indexes to data blocks. This constant wad originally defined in the .c and not the .h because files outside
// of state.c don't deal with data blocks. It was moved to the .h file because it was useful to define MAX_FILE_SIZE
// I don't like it this way very much, because many files might include state.h and they won't need MAX_INDIRECT_BLOCKS
// because, again, they don't deal with data blocks. TODO: is this ok?
#define MAX_INDIRECT_BLOCKS (BLOCK_SIZE / sizeof(int))

#define MAX_FILE_SIZE (BLOCK_SIZE * (INODE_DIRECT_REFERENCES + MAX_INDIRECT_BLOCKS))  

void state_init();
void state_destroy();

int inode_create(inode_type n_type);
int inode_delete(int inumber);
int inode_clear_file_contents(inode_t *inode);
inode_t *inode_get(int inumber);
ssize_t inode_write(inode_t *inode, void const *buffer, size_t to_write, size_t file_offset);
ssize_t inode_read(inode_t *inode, void *buffer, size_t to_read, size_t file_offset);

int clear_dir_entry(int inumber, int sub_inumber);
int add_dir_entry(int inumber, int sub_inumber, char const *sub_name);
int find_in_dir(int inumber, char const *sub_name);

int data_block_alloc();
int data_block_free(int block_number);
void *data_block_get(int block_number);

int add_to_open_file_table(int inumber, size_t offset);
int remove_from_open_file_table(int fhandle);
open_file_entry_t *get_open_file_entry(int fhandle);

#endif // STATE_H
