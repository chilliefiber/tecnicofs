#include "state.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

/* Persistent FS state  (in reality, it should be maintained in secondary
 * memory; for simplicity, this project maintains it in primary memory) */

/* I-node table */
static inode_t inode_table[INODE_TABLE_SIZE];
static char freeinode_ts[INODE_TABLE_SIZE];

/* Data blocks */
static char fs_data[BLOCK_SIZE * DATA_BLOCKS];
static char free_blocks[DATA_BLOCKS]; 

/* Volatile FS state */

static open_file_entry_t open_file_table[MAX_OPEN_FILES]; 
static char free_open_file_entries[MAX_OPEN_FILES]; 

/* Mutexes for allocation tables */
pthread_mutex_t freeinode_ts_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t free_blocks_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t free_open_file_entries_mutex = PTHREAD_MUTEX_INITIALIZER;
static inline bool valid_inumber(int inumber) {
    return inumber >= 0 && inumber < INODE_TABLE_SIZE;
}

static inline bool valid_block_number(int block_number) {
    return block_number >= 0 && block_number < DATA_BLOCKS;
}

static inline bool valid_file_handle(int file_handle) {
    return file_handle >= 0 && file_handle < MAX_OPEN_FILES;
}


/**
 * We need to defeat the optimizer for the insert_delay() function.
 * Under optimization, the empty loop would be completely optimized away.
 * This function tells the compiler that the assembly code being run (which is
 * none) might potentially change *all memory in the process*.
 *
 * This prevents the optimizer from optimizing this code away, because it does
 * not know what it does and it may have side effects.
 *
 * Reference with more information: https://youtu.be/nXaxk27zwlk?t=2775
 *
 * Exercise: try removing this function and look at the assembly generated to
 * compare.
 */
static void touch_all_memory() { __asm volatile("" : : : "memory"); }

/*
 * Auxiliary function to insert a delay.
 * Used in accesses to persistent FS state as a way of emulating access
 * latencies as if such data structures were really stored in secondary memory.
 */
static void insert_delay() {
    for (int i = 0; i < DELAY; i++) {
        touch_all_memory();
    }
}

/*
 * Initializes FS state
 */
int state_init() {
    if (pthread_mutex_lock(&freeinode_ts_mutex) != 0)
        return -1;
    for (size_t i = 0; i < INODE_TABLE_SIZE; i++) {
        freeinode_ts[i] = FREE;
    }
    if (pthread_mutex_unlock(&freeinode_ts_mutex) != 0)
        return -1;

    if (pthread_mutex_lock(&free_blocks_mutex) != 0)
        return -1;
    for (size_t i = 0; i < DATA_BLOCKS; i++) {
        free_blocks[i] = FREE;
    }
    if (pthread_mutex_unlock(&free_blocks_mutex) != 0)
        return -1;

    if (pthread_mutex_lock(&free_open_file_entries_mutex) != 0)
        return -1;
    for (size_t i = 0; i < MAX_OPEN_FILES; i++) {
        free_open_file_entries[i] = FREE;
    }
    if (pthread_mutex_unlock(&free_open_file_entries_mutex) != 0)
        return -1;
    return 0;
}
/**
 * Destroys the rwlocks of the inodes
 *
*/
static int inodes_destroy() {
    if (pthread_mutex_lock(&freeinode_ts_mutex) != 0) 
        return -1;
    int ret_code = 0;
    for (int inumber = 0; inumber < INODE_TABLE_SIZE; inumber++) {
        if ((inumber * (int) sizeof(allocation_state_t) % BLOCK_SIZE) == 0) 
            insert_delay(); // simulate storage access delay (to freeinode_ts)
        
        if (freeinode_ts[inumber] == TAKEN) {
            insert_delay(); // simulate storage access delay (to i-node)
            if (pthread_rwlock_destroy(&(inode_table[inumber].i_rwlock)) != 0)
                ret_code = -1;
        }
    }
    if (pthread_mutex_unlock(&freeinode_ts_mutex) != 0)
        return -1;
    return ret_code;
}

/**
 * Destroys the mutexes of the open files
 *
*/
static int open_files_destroy() {
    if (pthread_mutex_lock(&free_open_file_entries_mutex) != 0)
        return -1;

    int ret_code = 0;

    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (free_open_file_entries[i] == TAKEN) {
            if (pthread_mutex_destroy(&(open_file_table[i].of_mutex)) != 0)
                ret_code = -1;
        }
    }
    if (pthread_mutex_unlock(&free_open_file_entries_mutex) != 0)
        return -1;
    return ret_code;
}


/**
 * Destroys all mutexes/rwlocks
 *
*/
int state_destroy() { 
    int ret_code = inodes_destroy();
    if (open_files_destroy() == -1)
        ret_code = -1;
    return ret_code;
}

/**
 * Fills in a newly created inode.
 * Input:
 *  - inumber: inumber of the inode
 *  - n_type: the type of the node (file or directory)
 * Returns 0 on success, -1 on error
 */
static int inode_init(int inumber, inode_type n_type) {
    inode_table[inumber].i_node_type = n_type;
    if (n_type == T_DIRECTORY) {
        int b = data_block_alloc(); 
        if (b == -1) 
            return -1; 
        inode_table[inumber].i_size = BLOCK_SIZE; 
        inode_table[inumber].i_data_blocks[0] = b; 

        dir_entry_t *dir_entry = (dir_entry_t *)data_block_get(b);
        if (dir_entry == NULL)  
            return -1;
        
        for (size_t i = 0; i < MAX_DIR_ENTRIES; i++)  
            dir_entry[i].d_inumber = -1;
    } else {
        /* In case of a new file, simply sets its size to 0 */
        inode_table[inumber].i_size = 0;
        inode_table[inumber].i_data_blocks[0] = -1;
    }
    // doesn't matter if it's a directory or a new file, the blocks apart from the first one are empty
    for (int block_number = 1; block_number < INODE_DIRECT_REFERENCES; block_number++)
        inode_table[inumber].i_data_blocks[block_number] = -1;
    inode_table[inumber].i_indirect_data_block = -1;
    return 0;
}

/*
 * Creates a new i-node in the i-node table.
 * Input:
 *  - n_type: the type of the node (file or directory)
 * Returns:
 *  new i-node's number if successfully created, -1 otherwise
 */
int inode_create(inode_type n_type) {
    if (pthread_mutex_lock(&freeinode_ts_mutex) != 0) // placed here so that we don't lock/unlock every iteration
        return -1;
    int ret_code = -1;
    for (int inumber = 0; inumber < INODE_TABLE_SIZE; inumber++) {
        if ((inumber * (int) sizeof(allocation_state_t) % BLOCK_SIZE) == 0) 
            insert_delay(); // simulate storage access delay (to freeinode_ts)
        
        if (freeinode_ts[inumber] == FREE) {
            insert_delay(); // simulate storage access delay (to i-node)
            if (pthread_rwlock_init(&(inode_table[inumber].i_rwlock), NULL) != 0) { 
                pthread_mutex_unlock(&freeinode_ts_mutex);
                return -1;
            }
            if (pthread_rwlock_wrlock(&(inode_table[inumber].i_rwlock)) != 0){  
                pthread_rwlock_destroy(&(inode_table[inumber].i_rwlock)); 
                pthread_mutex_unlock(&freeinode_ts_mutex);
                return -1;
            }
            ret_code = inode_init(inumber, n_type);

            if (pthread_rwlock_unlock(&(inode_table[inumber].i_rwlock)) != 0 || ret_code == -1) {
                pthread_rwlock_destroy(&(inode_table[inumber].i_rwlock));
                pthread_mutex_unlock(&freeinode_ts_mutex);
                return -1;
            }
            ret_code = inumber;
            freeinode_ts[inumber] = TAKEN; // the reason this is here is because if there was an error previously we want it to be FREE
            break; 
        }
    }
    if (pthread_mutex_unlock(&freeinode_ts_mutex) != 0)
        return -1; // for simplification, if we can't unlock the mutex the entry stays TAKEN
    return ret_code;
}


/*
 * Deletes the i-node.
 * Input:
 *  - inumber: i-node's number
 * Returns: 0 if successful, -1 if failed
 */
int inode_delete(int inumber) {
    // simulate storage access delay (to i-node and freeinode_ts)
    insert_delay();
    insert_delay();
    if (pthread_mutex_lock(&freeinode_ts_mutex) != 0)
        return -1;
    if (!valid_inumber(inumber) || freeinode_ts[inumber] == FREE) {
        pthread_mutex_unlock(&freeinode_ts_mutex);
        return -1;
    }

    // we don't need to use inode_get, we already have the delay and the valid inumber check
    int ret_code = inode_clear_file_contents(&inode_table[inumber]); 

    if (pthread_rwlock_destroy(&(inode_table[inumber].i_rwlock)) != 0)
        ret_code = -1;

    freeinode_ts[inumber] = FREE;
    // this is at the end of the function to prevent a FREE entry from not having its rwlock destroyed. It wo 
    if (pthread_mutex_unlock(&freeinode_ts_mutex) != 0) 
        ret_code = -1; 
    return ret_code;
}

// Note there might be an off by one problem here if improperly used: if the original offset of a file is x and we want to access y bytes, 
// the final offset which we access is x+y-1
static inline int calculate_block_index(size_t file_offset) {
    return (int) file_offset / BLOCK_SIZE; // naughty cast. All casts signaled naughty are due to the original use of an int for block number
}

/*
 * Frees all blocks referenced by the indirect block, and it also frees the indirect block
 * Input:
 *  - indirect_block_number: block number of the indirect block
 *  - i_size: size of the file
 * Returns: 0 if successful, -1 if failed
 * 
 * Note: This function assumes that the indirect block has at least one reference to a block. It should not be called
 * if the indirect block was not in use
 */

static int free_indirect_block(int indirect_block_number, size_t i_size) {
    // Note that because of the required check that the indirect block is in use, inode->i_size -1 is always greater than 0
    int final_block_ix = calculate_block_index(i_size-1);

    final_block_ix -= INODE_DIRECT_REFERENCES; // now final_block_ix stores the index of the last block in the indirect block, and not the whole file

    // now we need to get the data from the indirect block. We treat it as an array of integers, since
    // we're using integers to index blocks, as per the original code
    int *indirect_block_data = (int*) data_block_get(indirect_block_number);

    if (!indirect_block_data) // an error ocurred
        return -1;
    
    int ret_code = 0;

    // this cleans all the data blocks referenced by the indirect block. block_index is the index in indirect_block_data
    // the actual block number is stored in indirect_block_data[block_index]
    for (int block_index = 0; block_index <= final_block_ix; block_index++) {
        if (data_block_free(indirect_block_data[block_index]) == -1) {
            ret_code = -1; // applying the same strategy of not returning while there might still be data to clean
        }
    }
    
    if (data_block_free(indirect_block_number) == -1)
        ret_code = -1;
    
    return ret_code;
}

/*
 Clears all the data on an inode
 Input:
   - pointer to inode
 Returns 0 on success, -1 on error
*/
int inode_clear_file_contents(inode_t *inode) {
    if (inode == NULL) 
        return -1;
    
    if (pthread_rwlock_wrlock(&inode->i_rwlock) != 0)
        return -1;
     
    if (inode->i_size == 0) {// the file was empty, nothing to do
        if (pthread_rwlock_unlock(&inode->i_rwlock) != 0)
            return -1;
        return 0;
    }

    int ret_code = 0; // return value
    // free direct blocks
    for (int block_number = 0; block_number < INODE_DIRECT_REFERENCES; block_number++) {
        // this will iterate over blocks that may not be used, but probably is fast enough that it doesn't matter
        if (inode->i_data_blocks[block_number] != -1 && data_block_free(inode->i_data_blocks[block_number]) == -1) {
            ret_code = -1; // this way, if we need to free more blocks we can do it and still return an error referring to this block
        }
    }
    
    if (inode->i_indirect_data_block != -1 && free_indirect_block(inode->i_indirect_data_block, inode->i_size) == -1) {
        ret_code = -1;
    }
    
    inode->i_size = 0;
    
    if (pthread_rwlock_unlock(&inode->i_rwlock) != 0) 
        return -1;
 
    return ret_code; 
}


static inline size_t get_offset_at_start_of_block(int block_ix) {
    return (size_t) (block_ix * BLOCK_SIZE); // naughty cast
}

static inline size_t calculate_block_offset(size_t file_offset) {
    return file_offset % BLOCK_SIZE;
}


static inline size_t calculate_bytes_to_access_in_block(size_t block_offset, size_t to_access) {
    return to_access > BLOCK_SIZE - block_offset ? BLOCK_SIZE - block_offset : to_access;
}

/*
 * Converts an index from 0 to MAX_INODE_REFERENCES + MAX_INDIRECT_REFERENCES - 1
 * inside the inode to the actual block number in the blocks data array. 
 * Input
 *  -inode the inode associated with the block we are looking for
 *  -block_ix the index
 *  -indirect_block_data Data pointed to by the indirect block in inode->i_indirect_data_block. Can be NULL and the function
 *   will still work as intended, but it might take a performance hit if it is NULL (see Note)
 * Returns: the block number, or -1 if there was an error 
 * Note: this function didn't originally include indirect_block_data as an argument. However, that meant it was not very good when 
 * used in a loop where we're looking for many blocks referenced in the indirect block, this is because it will always access 
 * the indirect block one time per block in the indirect block, and each access will have a delay. To optimise this problem,
 * when used in such a loop it should be called with indirect_block_data already pointing to the data of the indirect block
 */
static int get_block_number_from_inode_index(inode_t *inode, int block_ix, int *indirect_block_data) {
    if (block_ix < 0 || block_ix > INODE_DIRECT_REFERENCES + MAX_INDIRECT_BLOCKS - 1)
        return -1; // out of bounds block_ix

    if (block_ix * BLOCK_SIZE >= inode->i_size)
        return -1; // with this file size, there will be no block with such an index
    
    if (block_ix < INODE_DIRECT_REFERENCES)
        return inode->i_data_blocks[block_ix];

    // in this case the block has its block number stored in the indirect block    
    if (indirect_block_data == NULL) {
        indirect_block_data = (int*) data_block_get(inode->i_indirect_data_block);
        if (!indirect_block_data) 
            return -1;
    }
    block_ix -= INODE_DIRECT_REFERENCES; // now block_ix has the index inside of the indirect block
    return indirect_block_data[block_ix]; 
}

/**
 * Allocates a new data block for an inode
 * Input
 *  - block_ix index of the block in the inode (not in block table)
    - inode which needs a new data block
    - indirect_block_data data of the indirect block of the inode
  Returns -1 on error, or the allocated block's number in the block table
 */
static int allocate_new_block_for_writing(int block_ix, inode_t *inode, int **indirect_block_data) {
    int block_number = -1;
    if (block_ix < INODE_DIRECT_REFERENCES) { 
        inode->i_data_blocks[block_ix] = data_block_alloc(); // if this fails it will just store -1 there, which is ok because it's the value that's supposed to be there
        block_number = inode->i_data_blocks[block_ix]; // if this -1 the error will be signalled when we return block_number
    }
    else {
        if (block_ix == INODE_DIRECT_REFERENCES) { // in this case we are going to allocate the first block referenced in the indirect block                       
            inode->i_indirect_data_block = data_block_alloc(); // we need to allocate the indirect block itself first
            if (inode->i_indirect_data_block == -1) 
                return -1;
            *indirect_block_data = (int*) data_block_get(inode->i_indirect_data_block);  // I only need to get it for the allocation of 
            // first block referenced in the indirect block, for the other ones the variable is already filled, either here in a previous iteration or
            // right after the declaration of indirect_block_data in inode_write (the function that calls this one)
        }
        if (!(*indirect_block_data))  // now we made sure that indirect_block_data should be filled, if it's not it's an error
            return -1;
        block_number = data_block_alloc();
        // this is the case where we couldn't allocate the first data block referenced in the indirect block but we allocated in this function (in this execution)
        // the indirect block. We need to free the indirect block because it will contain no references to data blocks, as we couldn't allocate the first block
        if (block_number == -1 && block_ix == INODE_DIRECT_REFERENCES) 
            data_block_free(inode->i_indirect_data_block); // we don't need to check the value: we will return an error either way
        if (block_number == -1)
            return -1;
        (*indirect_block_data)[block_ix - INODE_DIRECT_REFERENCES] = block_number; // store the block number in the indirect block
    }
    return block_number;
}

/**
 * Writes data in the inode's blocks
 * Input
    -inode where we will write
    -buffer from where we copy the data
    -to_write number of bytes to write in the inode
    -file_offset starting offset of write operation
   Returns number of bytes written
 */
static size_t inode_write_in_blocks(inode_t *inode, const void *buffer, size_t to_write, size_t file_offset) {
    int first_block_ix = calculate_block_index(file_offset); 
    int last_block_ix = calculate_block_index(file_offset + to_write - 1);
    size_t block_offset = calculate_block_offset(file_offset); 
    int block_number = -1;
    void *block = NULL;
    int *indirect_block_data = NULL;
    if (last_block_ix >= INODE_DIRECT_REFERENCES) {
        indirect_block_data = (int*) data_block_get(inode->i_indirect_data_block);  // check for errors inside the loop
    }
    size_t to_write_in_block, bytes_written = 0; 

    for (int block_ix = first_block_ix; block_ix <= last_block_ix; block_ix++) {
        block_number = -1;
        // in this case we need to allocate a new block. Note that the condition inode->i_size < get_offset_at_start_of_block(block_ix)
        // should never happen, because then we would be creating a "hole" with no bytes in the middle of the file...
        if (inode->i_size <= get_offset_at_start_of_block(block_ix)) 
            block_number = allocate_new_block_for_writing(block_ix, inode, &indirect_block_data); // data_block_get checks for errors from this function
        else { // in this case the block should have already been allocated, and we just access the memory position like we do for reading
            if (block_ix >= INODE_DIRECT_REFERENCES && !indirect_block_data)  
                break;
            block_number = get_block_number_from_inode_index(inode, block_ix, indirect_block_data); // data_block_get checks this error for us
        }
        block = data_block_get(block_number);
        if (!block)
            break;
         
        to_write_in_block = calculate_bytes_to_access_in_block(block_offset, to_write);
        /* Perform the actual write */
        memcpy(block + block_offset, buffer, to_write_in_block);
        bytes_written += to_write_in_block;
        file_offset += to_write_in_block;
        buffer += to_write_in_block;
        to_write -= to_write_in_block;
        block_offset = 0; // offset is possibly not 0 in the first iteration, but in the other ones it's definitely 0
        if (file_offset > inode->i_size)
            inode->i_size = file_offset;
    }
    return bytes_written;
}

/* 
 Reads data from blocks of inode
 
 * Input
    -inode from where we will copy
    -buffer into which we copy the data
    -to_read number of bytes to read into the buffer
    -file_offset starting offset of read operation
   Returns number of bytes read
*/
static size_t inode_read_from_blocks(inode_t *inode, void *buffer, size_t to_read, size_t file_offset) {
    int first_block_ix = calculate_block_index(file_offset); // index of the first block from which we will be reading
    int last_block_ix = calculate_block_index(file_offset + to_read - 1); // index of the last block from which we will be reading
    size_t block_offset = calculate_block_offset(file_offset); // offset in the block we are currently reading from, which right now is first_block
    int block_number = -1;
    void *block = NULL;
    int *indirect_block_data = NULL;
    if (last_block_ix >= INODE_DIRECT_REFERENCES) 
        indirect_block_data = (int*) data_block_get(inode->i_indirect_data_block); // we check for errors later, inside the loop
        // The reasoning is that it's just an if statement so it's probably ok to check inside the loop (no accesses to memory or slow operations)
        // and this way it allows for the possibility to read bytes that come from direct blocks before crashing without adding lots of lines of code

    size_t to_read_from_block, bytes_read = 0;     
    for (int block_ix = first_block_ix; block_ix <= last_block_ix; block_ix++) { 
        if (block_ix >= INODE_DIRECT_REFERENCES && !indirect_block_data) // verification of data_block_get errors for the indirect_block_data
            break;
        block_number = get_block_number_from_inode_index(inode, block_ix, indirect_block_data); // we don't check for an error here: data_block_get does that for us
        block = data_block_get(block_number);
        if (!block)
            break;
        to_read_from_block = calculate_bytes_to_access_in_block(block_offset, to_read);
        /* Perform the actual read */
        memcpy(buffer, block + block_offset, to_read_from_block);
        bytes_read += to_read_from_block;
        buffer += to_read_from_block;
        file_offset += to_read_from_block;
        to_read -= to_read_from_block;
        block_offset = 0; // offset is possibly not 0 in the first iteration, but in the other ones it's definitely 0
    }
    return bytes_read;
}

/**
 * Copies the whole contents of the inode into a file in an external fs
 * Input
 * -inode to be copied
 * -dest_file external file
 * Returns -1 on error, 0 on success
 */
int inode_dump(inode_t *inode, FILE *dest_file) {
    if (inode == NULL)
        return -1;
    if (pthread_rwlock_rdlock(&(inode->i_rwlock)) != 0)
        return -1;
    if (inode->i_size == 0) {
        if (pthread_rwlock_unlock(&(inode->i_rwlock)) != 0)
            return -1; 
        return 0;
    }
    int last_block_ix = calculate_block_index(inode->i_size - 1); // see this function for an explanation for the -1
    int block_number = -1, ret_code = 0;
    void *block = NULL;
    int *indirect_block_data = NULL;
    if (last_block_ix >= INODE_DIRECT_REFERENCES) { 
        // in this case we check for errors immediately, because either we can copy the whole file or not
        if ((indirect_block_data = (int*) data_block_get(inode->i_indirect_data_block)) == NULL) {
            pthread_rwlock_unlock(&inode->i_rwlock);
            return -1;
        }
    }
    
    size_t to_read_from_block, block_offset = 0, to_read = inode->i_size; 
    for (int block_ix = 0; block_ix <= last_block_ix; block_ix++) { 
        block_number = get_block_number_from_inode_index(inode, block_ix, indirect_block_data); // we don't check for an error here: data_block_get does that for us
        block = data_block_get(block_number);
        if (!block) {
            ret_code = -1;
            break;
        }
        to_read_from_block = calculate_bytes_to_access_in_block(block_offset, to_read);
        if (fwrite(block, 1, to_read_from_block, dest_file) < to_read_from_block) {
            ret_code = -1; // there was an error writing to the destination file
            break;
        }
        to_read -= to_read_from_block;
    }
    if (pthread_rwlock_unlock(&inode->i_rwlock) != 0)
        ret_code = -1;
    return ret_code;
}

/**
 Write bytes from a buffer to the inode
 Input:
 - inode into which we write
 - buffer from which we want to copy 
 - to_write number of bytes to write
 - file_offset starting offset of write operation
 - append boolean that says if we should ignore the offset and write into the end of the file
 Returns: number of bytes written on success, -1 on error
 */
ssize_t inode_write(inode_t *inode, void const *buffer, size_t to_write, size_t file_offset, bool append) {
    if (inode == NULL)  
        return -1;
    if (pthread_rwlock_wrlock(&inode->i_rwlock) != 0) {
        return -1;
    }
    if (append)
        file_offset = inode->i_size;
    else if (file_offset > inode->i_size) {// in this case we are trying to make a "hole" in the file, writing past its end
        pthread_rwlock_unlock(&inode->i_rwlock);
        return -1;
    }
    if (file_offset + to_write > MAX_FILE_SIZE)  
        to_write = MAX_FILE_SIZE - file_offset;
    ssize_t ret_code = 0;
    if (to_write == 0) {
        if (pthread_rwlock_unlock(&inode->i_rwlock) != 0)
            ret_code = -1;
        return ret_code;
    }

    size_t bytes_written = inode_write_in_blocks(inode, buffer, to_write, file_offset);

    if (pthread_rwlock_unlock(&inode->i_rwlock) != 0)
        return -1;
    
    if (bytes_written == 0) // if bytes_written is 0 at this point there was an error before we could write anything
        return -1;

    return (ssize_t) bytes_written;
}

/**
 * Read bytes from the inode into a buffer.
 * Input:
 * -inode from which we read bytes
 * -buffer into which we write
 * file_offset starting offset of read operation
 * append boolean that says if we should ignore the offset and point it at end of file
 */
ssize_t inode_read(inode_t *inode, void *buffer, size_t to_read, size_t file_offset, bool append) {
    if (inode == NULL) 
        return -1;
    if (append)
        return 0; // we can't read any bytes from a file opened for appending
    if (pthread_rwlock_rdlock(&inode->i_rwlock) != 0) 
        return -1;
    // this might happen if someone in another thread truncates the file between someone else calling this function and the lock on the inode
    if (file_offset > inode->i_size) {  
        pthread_rwlock_unlock(&inode->i_rwlock);
        return -1;
    }                   
    size_t available_bytes = inode->i_size - file_offset;
    if (to_read > available_bytes)
        to_read = available_bytes;
    if (to_read == 0) {
        if (pthread_rwlock_unlock(&inode->i_rwlock) != 0)
            return -1;
        return 0;
    }
    size_t bytes_read = inode_read_from_blocks(inode, buffer, to_read, file_offset); 
    if (pthread_rwlock_unlock(&inode->i_rwlock) != 0)
        return -1;
    // in this case there was an error, because there were bytes to be read that we couldn't read
    if (bytes_read == 0) 
        return -1;
    return (ssize_t) bytes_read;
} 


/*
 * Returns a pointer to an existing i-node.
 * Input:
 *  - inumber: identifier of the i-node
 * Returns: pointer if successful, NULL if failed
 */
inode_t *inode_get(int inumber) {
    if (!valid_inumber(inumber)) {
        return NULL;
    }

    insert_delay(); // simulate storage access delay to i-node
    return &inode_table[inumber];
}

/*
 * Adds an entry to the i-node directory data.
 * Input:
 *  - inumber: identifier of the i-node
 *  - sub_inumber: identifier of the sub i-node entry
 *  - sub_name: name of the sub i-node entry
 * Returns: SUCCESS or FAIL
 */
int add_dir_entry(int inumber, int sub_inumber, char const *sub_name) {
    if (!valid_inumber(inumber) || !valid_inumber(sub_inumber)) {
        return -1;
    }

    if (strlen(sub_name) == 0) {
        return -1;
    }
    insert_delay(); // simulate storage access delay to i-node with inumber

    if (pthread_rwlock_wrlock(&(inode_table[inumber].i_rwlock)) != 0)
        return -1;    
    if (inode_table[inumber].i_node_type != T_DIRECTORY) {
        pthread_rwlock_unlock(&(inode_table[inumber].i_rwlock));
        return -1;
    }

    /* Locates the block containing the directory's entries */
    dir_entry_t *dir_entry =
        (dir_entry_t *)data_block_get(inode_table[inumber].i_data_blocks[0]);
    if (dir_entry == NULL) {
        pthread_rwlock_unlock(&(inode_table[inumber].i_rwlock));
        return -1;
    }

    int ret_code = -1;
    /* Finds and fills the first empty entry */
    for (size_t i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (dir_entry[i].d_inumber == -1) {
            dir_entry[i].d_inumber = sub_inumber;
            strncpy(dir_entry[i].d_name, sub_name, MAX_FILE_NAME - 1);
            dir_entry[i].d_name[MAX_FILE_NAME - 1] = 0;
            ret_code = 0;
            break;
        }
    }

    if (pthread_rwlock_unlock(&(inode_table[inumber].i_rwlock)) != 0)
        ret_code = -1;
    return ret_code; 
}

/* Looks for a given name inside a directory
 * Input:
 * 	- parent directory's i-node number
 * 	- name to search
 * 	Returns i-number linked to the target name, -1 if not found
 */
int find_in_dir(int inumber, char const *sub_name) { 
    insert_delay(); // simulate storage access delay to i-node with inumber
    if (!valid_inumber(inumber)) {
        return -1;
    }
    if (pthread_rwlock_rdlock(&(inode_table[inumber].i_rwlock)) != 0)
        return -1;    
    if (inode_table[inumber].i_node_type != T_DIRECTORY) {
        pthread_rwlock_unlock(&(inode_table[inumber].i_rwlock));
        return -1;
    }
    /* Locates the block containing the directory's entries */
    dir_entry_t *dir_entry =
        (dir_entry_t *)data_block_get(inode_table[inumber].i_data_blocks[0]);
    if (dir_entry == NULL) {
        pthread_rwlock_unlock(&(inode_table[inumber].i_rwlock));
        return -1;
    }

    /* Iterates over the directory entries looking for one that has the target
     * name */
    int ret_value = -1;
    for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
        if ((dir_entry[i].d_inumber != -1) &&
            (strncmp(dir_entry[i].d_name, sub_name, MAX_FILE_NAME) == 0)) {
            ret_value = dir_entry[i].d_inumber;
            break;
        }
    }
    if (pthread_rwlock_unlock(&(inode_table[inumber].i_rwlock)) != 0)
        ret_value = -1;
    return ret_value;
}

/*
 * Allocated a new data block
 * Returns: block index if successful, -1 otherwise
 */
int data_block_alloc() {
    if (pthread_mutex_lock(&free_blocks_mutex) != 0)
        return -1;
    for (int i = 0; i < DATA_BLOCKS; i++) {
        if (i * (int) sizeof(allocation_state_t) % BLOCK_SIZE == 0) {
            insert_delay(); // simulate storage access delay to free_blocks
        }

        if (free_blocks[i] == FREE) {
            free_blocks[i] = TAKEN;
            if (pthread_mutex_unlock(&free_blocks_mutex) !=0) {
                return -1; // for simplicity if there is an error here we don't put it back to FREE
            }
            return i;
        }
    }
    pthread_mutex_unlock(&free_blocks_mutex); // no check because we will return an error either way
    return -1;
}

/* Frees a data block
 * Input
 * 	- the block index
 * Returns: 0 if success, -1 otherwise
 */
int data_block_free(int block_number) {
    if (!valid_block_number(block_number)) {
        return -1;
    }

    insert_delay(); // simulate storage access delay to free_blocks
    if (pthread_mutex_lock(&free_blocks_mutex) != 0)
        return -1;
    free_blocks[block_number] = FREE;
    if (pthread_mutex_unlock(&free_blocks_mutex) != 0)
        return -1;
    return 0;
}

/* Returns a pointer to the contents of a given block
 * Input:
 * 	- Block's index
 * Returns: pointer to the first byte of the block, NULL otherwise
 */
void *data_block_get(int block_number) {
    if (!valid_block_number(block_number)) {
        return NULL;
    }

    insert_delay(); // simulate storage access delay to block
    return &fs_data[block_number * BLOCK_SIZE];
}

/* Add new entry to the open file table
 * Inputs:
 * 	- I-node number of the file to open
 * 	- Initial offset
 *      - Boolean value indicating if the file was opened in append mode
 * Returns: file handle if successful, -1 otherwise
 */
open_file_entry_t *add_to_open_file_table(int *fhandle) {
    if (pthread_mutex_lock(&free_open_file_entries_mutex) != 0)
        return NULL;
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (free_open_file_entries[i] == FREE) {
            free_open_file_entries[i] = TAKEN;
            pthread_mutex_init(&(open_file_table[i].of_mutex), NULL); // always returns 0
            if (pthread_mutex_unlock(&free_open_file_entries_mutex) != 0) { // if there is an error here for simplicity it stays TAKEN
                return NULL;
            }
            *fhandle = i;
            return &open_file_table[i];
        }
    }
    pthread_mutex_unlock(&free_open_file_entries_mutex);
    return NULL;
}

/* Frees an entry from the open file table
 * Inputs:
 * 	- file handle to free/close
 * Returns 0 is success, -1 otherwise
 */
int remove_from_open_file_table(int fhandle) {
    if (pthread_mutex_lock(&free_open_file_entries_mutex) != 0)
        return -1;
    if (!valid_file_handle(fhandle) ||
        free_open_file_entries[fhandle] != TAKEN) {
        pthread_mutex_unlock(&free_open_file_entries_mutex);
        return -1;
    }
    int ret_code = 0;
    if (pthread_mutex_destroy(&(open_file_table[fhandle].of_mutex)) != 0)
        ret_code = -1;
    free_open_file_entries[fhandle] = FREE;
    if (pthread_mutex_unlock(&free_open_file_entries_mutex) != 0)
        return -1;
    return ret_code;
}

/* Returns pointer to a given entry in the open file table
 * Inputs:
 * 	 - file handle
 * Returns: pointer to the entry if sucessful, NULL otherwise
 * Note: see inode_get's note, it also applies to this function
 */
open_file_entry_t *get_open_file_entry(int fhandle) {
    if (!valid_file_handle(fhandle)) {
        return NULL;
    }
    return &open_file_table[fhandle];
}
