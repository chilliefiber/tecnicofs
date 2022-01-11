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
    // POSSIBLE CRITICAL SECTION start inode_table, inside inode_create
    int root = inode_create(T_DIRECTORY);
    if (root != ROOT_DIR_INUM) { // o state seleciona o inumber sequencialmente, começando no 0
                                 // se não devolver 0 significa que o 0 está TAKEN, logo o fs ja foi inicializado
                                 // num programa sequencial isto nao acontece porque o state_init coloca os inodes a FREE
                                 // mas com threads podia acontecer
        return -1;
    }

    return 0;
}

int tfs_destroy() { 
    for (int i = 0; i < MAX_OPEN_FILES; i++) 
        if (pthread_mutex_destroy(&file_entry_mutex[i]) != 0)
            return -1;
    
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

int tfs_open(char const *name, int flags) {
    int inum;
    size_t offset;
    bool append = false;
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
        if (inode == NULL) { // POSSIBLE CRITICAL
            return -1;

        /* Trucate (if requested) */
        if (flags & TFS_O_TRUNC) {
            if (inode_clear_file_contents(inode, inum) == -1) 
                return -1;
        }
        /* Determine initial offset */
        if (flags & TFS_O_APPEND) {
            offset = inode_get_size(inode, inum);
            append = true;
        } else {
            offset = 0;
        }
    } else if (flags & TFS_O_CREAT) {
        /* The file doesn't exist; the flags specify that it should be created*/
        /* Create inode */
        inum = inode_create(T_FILE);
        if (inum == -1) {
            pthread_mutex_unlock(&root_dir_mutex); // no need to check return value, we will return an error either way
            return -1;
        }
        /* Add entry in the root directory */
        if (add_dir_entry(ROOT_DIR_INUM, inum, name + 1) == -1) { // no need to check return values here, we will return an error either way
            inode_delete(inum); 
            pthread_mutex_unlock(&root_dir_mutex); 
            return -1;
        }
        if (pthread_mutex_unlock(&root_dir_mutex) != 0) {
            // DUVIDA: devo apagar aqui o inode?
            return -1;
        }
        offset = 0;
    } else {
        pthread_mutex_unlock(&root_dir_mutex); // no need to check return value, we will return an error either way
        return -1;
    }

    /* Finally, add entry to the open file table and
     * return the corresponding handle */
    return add_to_open_file_table(inum, offset, append);

    /* Note: for simplification, if file was created with TFS_O_CREAT and there
     * is an error adding an entry to the open file table, the file is not
     * opened but it remains created */
}

// Note: this function doesn't actually access the open_file_entry_t inside state.c
// As such, we don't need to lock the open_file_entry_t here
int tfs_close(int fhandle) { return remove_from_open_file_table(fhandle); }

ssize_t tfs_write(int fhandle, void const *buffer, size_t to_write) {
    return fd_write(fhandle, buffer, to_write);
}

ssize_t tfs_read(int fhandle, void *buffer, size_t len) {
     
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        pthread_mutex_unlock(&file_entry_mutex[fhandle]);
        return -1;
    }

    // here I am trusting that the open file entry stores a valid inumber 
    /* From the open file table entry, we get the inode */
    inode_t *inode = inode_get(file->of_inumber);
    if (inode == NULL) {
        pthread_rwlock_unlock(&inode_rwlock[file->of_inumber]);
        pthread_mutex_unlock(&file_entry_mutex[fhandle]);
        return -1;
    }

    char error = 0;
    /* Determine how many bytes to read */
    size_t to_read = inode->i_size - file->of_offset; // right now to_read saves the amount of bytes we CAN read from the file, starting at offset and ending in the last byte
    if (to_read > len) {
        to_read = len; // making sure that we don't try to write outside the buffer
    }
    if (to_read == 0) {    
        if (pthread_rwlock_unlock(&inode_rwlock[file->of_inumber]) != 0)
            error = 1;
        if (pthread_mutex_unlock(&file_entry_mutex[fhandle]) != 0)
            error = 1;
        return error ? -1 : 0; 
    }
    
    // COPIED TO HERE
    ssize_t read = inode_read(inode, buffer, to_read, file->of_offset);

    if (pthread_rwlock_unlock(&inode_rwlock[file->of_inumber]) != 0) 
        error = 1; 

    if (read > 0) {
        /* The offset associated with the file handle is
         * incremented accordingly */
        file->of_offset += (size_t) read;
    }

    if (pthread_mutex_unlock(&file_entry_mutex[fhandle]) != 0)
        error = 1;
    return error ? -1 : read;
}

// TODO creating an array the size of the file is very crude, possibly define MAX_READ and make multiple reads

// I didn't use tfs_read because to know the length of the file I needed the inode, and that implies one access
// to memory. In reality the inode would probably be cached, but here if I got the length and then called tfs_read 
// there would be 2 accesses to memory to get the same inode
int tfs_copy_to_external_fs(char const *source_path, char const *dest_path) {
    int fhandle = tfs_open(source_path, 0); // flags == 0 means open for reading at beginning 
    if (fhandle == -1)
        return -1;
    int error_code = fd_copy(fhandle, dest_path);
    // the mutex here will only be rarely, if ever needed. this is because we just returned this fhandle from
    // tfs_open and as such no one else has this information (the handle). However, we keep it here to prevent
    // cases where some other thread had this same fhandle related to a previous use of the same index (sort of but not really like the ABA problem)
    if (pthread_mutex_lock(&file_entry_mutex[fhandle]) != 0) {
        tfs_close(fhandle); // we're not checking the return value because we're going to throw an error anyway
        return -1;
    }

    if (pthread_rwlock_rdlock(&inode_rwlock[source_file->of_inumber]) != 0) {
        tfs_close(fhandle); // we're not checking the return value because we're going to throw an error anyway
        pthread_mutex_unlock(&file_entry_mutex[fhandle]);
        return -1;
    }
    inode_t *inode = inode_get(source_file->of_inumber);

    if (inode == NULL) {
        pthread_rwlock_unlock(&inode_rwlock[source_file->of_inumber]);
        tfs_close(fhandle); // we're not checking the return value because we're going to throw an error anyway
        pthread_mutex_unlock(&file_entry_mutex[fhandle]);
        return -1;
    }

    source_file->of_offset = 0; // DEFENSIVE prevent weird bug mentioned above when we lock the mutex
    
    // now everything related to the source file has been retrieved, we can create the destination file

    FILE *dest_file = fopen(dest_path, "w");
    if (!dest_file) {
        pthread_rwlock_unlock(&inode_rwlock[source_file->of_inumber]);
        tfs_close(fhandle); // not checking the error because we will return an error either way
        pthread_mutex_unlock(&file_entry_mutex[fhandle]);
        return -1; // TODO possibly perror
    }

    int ret_code = 0; 
    // if the file was empty
    if (inode->i_size == 0) {
        if (pthread_rwlock_unlock(&inode_rwlock[source_file->of_inumber]) != 0)
            ret_code = -1;
        if (tfs_close(fhandle) == -1)
            ret_code = -1;
        if (pthread_mutex_unlock(&file_entry_mutex[fhandle]) != 0)
            ret_code = -1;
        if (fclose(dest_file) == EOF)
            ret_code = -1;
        return ret_code;
    }

    char file_contents[inode->i_size];

    size_t to_read = inode->i_size, dest_offset = 0;

    ssize_t read = 0;
   
    while ((read = inode_read(inode, file_contents + dest_offset, to_read, source_file->of_offset)) >= 0) {
        to_read -= (size_t) read;
        if (to_read == 0)
            break;
        dest_offset += (size_t) read;
        source_file->of_offset += (size_t) read;
    }
  
    size_t inode_size = inode->i_size; // this is just so we can unlock the inode earlier
    if (pthread_rwlock_unlock(&inode_rwlock[source_file->of_inumber]) != 0)
        ret_code = -1;
    if (tfs_close(fhandle) == -1) 
        ret_code = -1;
    if (pthread_mutex_unlock(&file_entry_mutex[fhandle]) != 0)
        ret_code = -1;

    // if we read some bytes, we will write them, even if it's not the whole file. TODO ask if this is appropriate behaviour
    if (to_read < inode_size) 
        // inode->i_size - to_read is the number of bytes actually written, 1 is sizeof(char)
        // if it didn't write exactly inode->i_size bytes, even if to_read wasn't 0 we would have set ret_code to -1 later on because there are still bytes to be read so we do it immediately here
        if (fwrite(file_contents, 1, inode_size - to_read, dest_file) < inode_size)
            ret_code = -1;

    if (fclose(dest_file) == EOF)
        ret_code = -1;
    if (to_read != 0) // there were still bytes to be read
        ret_code = -1;

    // NEW
    tfs_close(fhandle); // we're not checking the return value because we're going to throw an error anyway
    return ret_code; 
}
