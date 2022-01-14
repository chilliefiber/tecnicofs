#include "operations.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

pthread_mutex_t root_dir_mutex = PTHREAD_MUTEX_INITIALIZER;
int tfs_init() {
    if (state_init() != 0)
        return -1;
    /* create root inode */
    int root = inode_create(T_DIRECTORY);
    if (root != ROOT_DIR_INUM) { 
        return -1;
    }

    return 0;
}

int tfs_destroy() { 
    return state_destroy();
}

static bool valid_pathname(char const *name) {
    return name != NULL && strlen(name) > 1 && name[0] == '/';
}

int tfs_lookup(char const *name) {
    if (!valid_pathname(name)) {
        return -1;
    }

    // skip the initial '/' character
    name++;

    return find_in_dir(ROOT_DIR_INUM, name);
}

static int file_init(int inumber, bool append) {
    int fhandle;
    open_file_entry_t *file = add_to_open_file_table(&fhandle);
    if (file == NULL)
        return -1;
    if (pthread_mutex_lock(&(file->of_mutex)) != 0) // POSSIBLE CRITICAL SECTION I think it's not a critical section because we just created the file, and no one has its fhandle
        return -1;
    file->of_inumber = inumber;
    file->of_offset = 0; // we ignore the offset if it's a file opened for appending
    file->of_append = append;
    if (pthread_mutex_unlock(&(file->of_mutex)) != 0) {
        tfs_close(fhandle);
        return -1;
    }
    return fhandle;
}

int tfs_open(char const *name, int flags) {
    int inum;
    /* Checks if the path name is valid */
    if (!valid_pathname(name)) { // note that thanks to this check it is impossible to open the root directory. 
        return -1;
    }

    // to prevent the creation of 2 files with the same name we lock
    // the root directory here. This way the first to lock will create the
    // file, and the second one will receive the inum in tfs_lookup 
    if (pthread_mutex_lock(&root_dir_mutex) != 0)
        return -1;
    inum = tfs_lookup(name);
    if (inum >= 0) {
        /* The file already exists */
        if (pthread_mutex_unlock(&root_dir_mutex) != 0)
            return -1;
        inode_t *inode = inode_get(inum);
        if (inode == NULL) 
            return -1;
        /* Trucate (if requested) */
        if (flags & TFS_O_TRUNC) {
            if (inode_clear_file_contents(inode) == -1) 
                return -1;
        }
    } else if (flags & TFS_O_CREAT) {
        /* The file doesn't exist; the flags specify that it should be created*/
        /* Create inode */
        inum = inode_create(T_FILE);
        if (inum == -1) {
            pthread_mutex_unlock(&root_dir_mutex); 
            return -1;
        }
        /* Add entry in the root directory */
        if (add_dir_entry(ROOT_DIR_INUM, inum, name + 1) == -1) { 
            inode_delete(inum); 
            pthread_mutex_unlock(&root_dir_mutex); 
            return -1;
        }
        if (pthread_mutex_unlock(&root_dir_mutex) != 0) {
            inode_delete(inum);
            return -1;
        }
    } else {
        pthread_mutex_unlock(&root_dir_mutex); 
        return -1;
    }
     
    return file_init(inum, flags & TFS_O_APPEND);

    /* Note: for simplification, if file was created with TFS_O_CREAT and there
     * is an error adding an entry to the open file table, the file is not
     * opened but it remains created */
}


int tfs_close(int fhandle) { return remove_from_open_file_table(fhandle); }

ssize_t tfs_write(int fhandle, void const *buffer, size_t len) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) 
        return -1;
    if (pthread_mutex_lock(&(file->of_mutex)) != 0)
        return -1;

    inode_t *inode = inode_get(file->of_inumber);
    if (inode == NULL) { 
        pthread_mutex_unlock(&(file->of_mutex)); // no need to check for error values
        return -1;
    }
    ssize_t bytes_written = inode_write(inode, buffer, len, file->of_offset, file->of_append); 
    if (bytes_written > 0)
        file->of_offset += (size_t) bytes_written;
    if (pthread_mutex_unlock(&(file->of_mutex)) != 0) 
        bytes_written = -1; 
    return bytes_written;
}

ssize_t tfs_read(int fhandle, void *buffer, size_t len) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) 
        return -1;
    
    if (pthread_mutex_lock(&(file->of_mutex)) != 0)
        return -1;

    inode_t *inode = inode_get(file->of_inumber);
    if (inode == NULL) { 
        pthread_mutex_unlock(&(file->of_mutex)); // no need to check for error values
        return -1;
    }
    ssize_t bytes_read = inode_read(inode, buffer, len, file->of_offset, file->of_append);
    
    if (bytes_read > 0)
        file->of_offset += (size_t) bytes_read;
    
    if (pthread_mutex_unlock(&(file->of_mutex)) != 0)
        bytes_read = -1; 
    
    return bytes_read; 
}

int tfs_copy_to_external_fs(char const *source_path, char const *dest_path) {
    int fhandle = tfs_open(source_path, 0); // flags == 0 means open for reading at beginning 
    if (fhandle == -1)
        return -1;
    open_file_entry_t *source_file = get_open_file_entry(fhandle);
    if (source_file == NULL)
        return -1;
    
    if (pthread_mutex_lock(&(source_file->of_mutex)) != 0) // MAYBE REMOVE IF WE CAN ASSUME option as per Daniel's email:
        return -1;
    
    inode_t *inode = inode_get(source_file->of_inumber);

    if (inode == NULL) {
        pthread_mutex_unlock(&source_file->of_mutex);
        return -1;
    }
    // now we know there is an inode for this source file, so we can create the new file in the external fs
    FILE *dest_file = fopen(dest_path, "w");
    if (!dest_file) {
        pthread_mutex_unlock(&source_file->of_mutex);
        return -1; 
    }

    int ret_code = inode_dump(inode, dest_file);

    if (pthread_mutex_unlock(&source_file->of_mutex) != 0)
        ret_code = -1;
    if (tfs_close(fhandle) != 0)
        ret_code = -1;
    if (fclose(dest_file) == EOF)
        ret_code = -1;
    return ret_code; 
}
