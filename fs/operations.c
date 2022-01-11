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
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) // POSSIBLE CRITICAL
        return -1;
    if (pthread_mutex_lock(&file_entry_mutex[fhandle]) != 0)
        return -1;

    inode_t *inode = inode_get(file->of_inumber);
    if (inode == NULL) { // POSSIBLE CRITICAL
        pthread_mutex_unlock(&file_entry_mutex[fhandle]); // no need to check for error values
        return -1;
    }
    ssize_t ret_value = inode_write(file, buffer, to_write); 
    pthread_mutex_unlock(&file_entry_mutex[fhandle]); // 
    return ret_value;
}

ssize_t tfs_read(int fhandle, void *buffer, size_t len) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL)  // POSSIBLE CRITICAL
        return -1;
    
    if (pthread_mutex_lock(&file_entry_mutex[fhandle]) != 0)
        return -1;

    inode_read();

    pthread_mutex_unlock(&file_entry_mutex[fhandle]); // should I check?
    
    return (ssize_t) bytes_read; 
}


// I didn't use tfs_read because to know the length of the file I needed the inode, and that implies one access
// to memory. In reality the inode would probably be cached, but here if I got the length and then called tfs_read 
// there would be 2 accesses to memory to get the same inode. More importantly, it would create a data race because
// if we called inode_get_size here and then tfs_read the size of the file could change between the accesses to the inode
int tfs_copy_to_external_fs(char const *source_path, char const *dest_path) {
    int fhandle = tfs_open(source_path, 0); // flags == 0 means open for reading at beginning 
    if (fhandle == -1)
        return -1;
    open_file_entry_t *source_file = get_open_file_entry(fhandle);
    if (source_file == NULL)
        return -1;
    
    // the mutex here will only be rarely, if ever needed. this is because we just returned this fhandle from
    // tfs_open and as such no one else has this information (the handle). However, we keep it here to prevent
    // cases where some other thread had this same fhandle related to a previous use of the same index (sort of but not really like the ABA problem)
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
        pthread_mutex_unlock(&source_file);
        return -1; // TODO possibly perror
    }

    int ret_code = inode_dump(inode, dest_file);

    if (pthread_rwlock_rdlock(&inode_rwlock[source_file->of_inumber]) != 0) {
        pthread_mutex_unlock(&file_entry_mutex[fhandle]);
        fclose(dest_file);
        return -1;
    }
    int error_code = 0;
    if (inode->i_size == 0) {
        if (pthread_rwlock_unlock(&inode_rwlock[source_file->of_inumber]) != 0)
            error_code = -1;
        if (pthread_mutex_unlock(&file_entry_mutex[fhandle]) != 0)
            error_code = -1;
        if (fclose(dest_file) == EOF)
            error_code = -1;
        return error_code;
    }
    char buffer[BUFFER_SIZE];
    
    size_t bytes_left = inode->i_size, to_read, bytes_read;
    while (bytes_left > 0) {
        to_read = bytes_left > BUFFER_SIZE ? BUFFER_SIZE : bytes_left;
        bytes_read = inode_read(inode, source_file, to_read, buffer);
        if (bytes_read == 0)
            break;
        if (fwrite(buffer, 1, bytes_read, dest_file) < bytes_read)
            break;
        bytes_left -= bytes_read;
    }
   
    if (pthread_rwlock_unlock(&inode_rwlock[source_file->of_inumber]) != 0)
        error_code = -1;
    if (pthread_mutex_unlock(&file_entry_mutex[fhandle]) != 0)
        error_code = -1;
    if (fclose(dest_file) == EOF)
        error_code = -1;
    if (bytes_left != 0)
        error_code = -1;
    return error_code; 
    int ret_code = fd_copy(fhandle, dest_path);
    if (tfs_close(fhandle) == -1) 
        ret_code = -1; 
    return ret_code; 
}
