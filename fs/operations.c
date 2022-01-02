#include "operations.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int tfs_init() {
    state_init();

    /* create root inode */
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
    state_destroy();
    return 0;
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

    /* Checks if the path name is valid */
    if (!valid_pathname(name)) {
        return -1;
    }

    inum = tfs_lookup(name);
    if (inum >= 0) {
        /* The file already exists */
        inode_t *inode = inode_get(inum);
        if (inode == NULL) {
            return -1;
        }

        /* Trucate (if requested) */
        if (flags & TFS_O_TRUNC) {
            if (inode_clear_file_contents(inode) == -1)
                return -1;
        }
        /* Determine initial offset */
        if (flags & TFS_O_APPEND) {
            offset = inode->i_size;
        } else {
            offset = 0;
        }
    } else if (flags & TFS_O_CREAT) {
        /* The file doesn't exist; the flags specify that it should be created*/
        /* Create inode */
        inum = inode_create(T_FILE);
        if (inum == -1) {
            return -1;
        }
        /* Add entry in the root directory */
        if (add_dir_entry(ROOT_DIR_INUM, inum, name + 1) == -1) {
            inode_delete(inum);
            return -1;
        }
        offset = 0;
    } else {
        return -1;
    }

    /* Finally, add entry to the open file table and
     * return the corresponding handle */
    return add_to_open_file_table(inum, offset);

    /* Note: for simplification, if file was created with TFS_O_CREAT and there
     * is an error adding an entry to the open file table, the file is not
     * opened but it remains created */
}


int tfs_close(int fhandle) { return remove_from_open_file_table(fhandle); }

ssize_t tfs_write(int fhandle, void const *buffer, size_t to_write) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    /* From the open file table entry, we get the inode */
    inode_t *inode = inode_get(file->of_inumber);
    if (inode == NULL) {
        return -1;
    }

    /* Determine how many bytes to write */
    if (to_write + file->of_offset > MAX_FILE_SIZE) { 
        to_write = MAX_FILE_SIZE - file->of_offset;
    }

    ssize_t written = 0;
    
    if (to_write > 0) { 
        written = inode_write(inode, buffer, to_write, file->of_offset);
    }

    // right now written has the number of bytes written, or -1 if there was an error in inode_write
    if (written > 0) {
        /* The offset associated with the file handle is
         * incremented accordingly */
        file->of_offset += (size_t) written; // TODO 3: note that this might cause problems because the offset is only updated in the end, 
                                     // and if there are multiple clients accessing this there might be a race condition where
                                     // the real offset was changed, but file->of_offset wasn't yet updated. It might be wise
                                     // to alter it everytime we write to make it thread-safe. Talvez isto não faça assim tanto sentido
                                     // porque cada acesso multi-threaded vai ter um open file diferente para o mesmo ficheiro??
                                     // TODO dúvida: então escrevemos sempre no fim do ficheiro? R: falso, escrevemos sempre onde aponta o offset
                                     // deste open file, que pode não ser o fim do ficheiro penso eu
                                     // NOTE: there is a chance that file->of_offset == MAX_FILE_SIZE, this is ok it means that the file is full
    }
    
    return written; 
}


ssize_t tfs_read(int fhandle, void *buffer, size_t len) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    /* From the open file table entry, we get the inode */
    inode_t *inode = inode_get(file->of_inumber);
    if (inode == NULL) {
        return -1;
    }

    /* Determine how many bytes to read */
    size_t to_read = inode->i_size - file->of_offset; // right now to_read saves the amount of bytes we CAN read from the file, starting at offset and ending in the last byte
    if (to_read > len) {
        to_read = len; // making sure that we don't try to write outside the buffer
    }

    ssize_t read = 0;
    if (to_read > 0) {
        read = inode_read(inode, buffer, to_read, file->of_offset);
    }

    if (read > 0) {
        /* The offset associated with the file handle is
         * incremented accordingly */
        file->of_offset += (size_t) read;
    }

    return read;
}

// TODO creating an array the size of the file is very crude, possibly define MAX_READ and make multiple reads

// I didn't use tfs_read because to know the length of the file I needed the inode, and that implies one access
// to memory. In reality the inode would probably be cached, but here if I got the length and then called tfs_read 
// there would be 2 accesses to memory to get the same inode
int tfs_copy_to_external_fs(char const *source_path, char const *dest_path) {
    int fhandle = tfs_open(source_path, 0); // flags == 0 means open for reading at beginning 
    if (fhandle == -1)
        return -1;
    open_file_entry_t *source_file = get_open_file_entry(fhandle);

    if (source_file == NULL) {
        tfs_close(fhandle); // we're not checking the return value because we're going to throw an error anyway
        return -1;
    }

    inode_t *inode = inode_get(source_file->of_inumber);

    if (inode == NULL) {
        tfs_close(fhandle); // we're not checking the return value because we're going to throw an error anyway
        return -1;
    }
    // now everything related to the source file has been retrieved, we can create the destination file

    FILE *dest_file = fopen(dest_path, "w");
    if (!dest_file) {
        tfs_close(fhandle); // not checking the error because we will return an error either way
        return -1; // TODO possibly perror
    }

    int ret_code = 0; 
    // if the file was empty
    if (inode->i_size == 0) {
        if (tfs_close(fhandle) == -1)
            ret_code = -1;
        if (fclose(dest_file) == EOF)
            ret_code = -1;
        return ret_code;
    }

    char file_contents[inode->i_size];

    size_t to_read = inode->i_size, buffer_offset = 0;

    ssize_t read = 0;
   
    // TODO behaviour when someone opened this file with truncate while we were reading: 
    // right now it will read until someone truncates and then crash (once state.c is finally mt safe)
    // returning -1 
    while ((read = inode_read(inode, file_contents + buffer_offset, to_read, source_file->of_offset)) >= 0) {
        to_read -= (size_t) read;
        if (to_read == 0)
            break;
        buffer_offset += (size_t) read;
        source_file->of_offset += (size_t) read;
    }
   
    if (tfs_close(fhandle) == -1) 
        ret_code = -1;
    // if we read some bytes, we will write them, even if it's not the whole file. TODO ask if this is appropriate behaviour
    if (to_read < inode->i_size) 
        // inode->i_size - to_read is the number of bytes actually written, 1 is sizeof(char)
        // if it didn't write exactly inode->i_size bytes, even if to_read wasn't 0 we would have set ret_code to -1 later on because there are still bytes to be read so we do it immediately here
        if (fwrite(file_contents, 1, inode->i_size - to_read, dest_file) < inode->i_size)
            ret_code = -1;

    if (fclose(dest_file) == EOF)
        ret_code = -1;
    if (to_read != 0) // there were still bytes to be read
        ret_code = -1;
    return ret_code; 
}
