#include "state.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>



/* Persistent FS state  (in reality, it should be maintained in secondary
 * memory; for simplicity, this project maintains it in primary memory) */

/* I-node table */
static inode_t inode_table[INODE_TABLE_SIZE]; // 1 trinco por posição
static char freeinode_ts[INODE_TABLE_SIZE]; // 1 trinco para todo o mapa

/* Data blocks */
static char fs_data[BLOCK_SIZE * DATA_BLOCKS]; // sem trinco?
static char free_blocks[DATA_BLOCKS]; // 1 trinco para todo o mapa

/* Volatile FS state */

// 1 trinco por posição
static open_file_entry_t open_file_table[MAX_OPEN_FILES]; // aqui o indice corresponde noutras funções ao fhandle: não está relacionado com inumber, é como
                                                          // o stdin é fd 0 mas não tem o inumber 0. penso que isto permita que o mesmo ficheiro tenha diferentes
                                                          // entradas no 3, de modo a permitir concorrência com offsets diferentes
// 1 trinco para toda a tabela
static char free_open_file_entries[MAX_OPEN_FILES]; // indice igual ao de cima para a mesma entrada

/* Mutexes for allocation tables */
pthread_mutex_t freeinode_ts_mutex;
pthread_mutex_t free_blocks_mutex;
pthread_mutex_t free_open_file_entries_mutex;

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
    pthread_mutex_init(&freeinode_ts_mutex, NULL); // this function always returns 0
    pthread_mutex_init(&free_blocks_mutex, NULL);
    pthread_mutex_init(&free_open_file_entries, NULL);
    

    // Note: in this function, which is only supposed to be called once, I lock the whole iteration  
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

int state_destroy() { /* destroys mutexes. will return an error if they are busy */
    if (pthread_mutex_destroy(&freeinode_ts_mutex) != 0) 
        return -1;
    if (pthread_mutex_destroy(&free_blocks_mutex) != 0)
        return -1;
    if (pthread_mutex_destroy(&free_open_file_entries_mutex) != 0)
        return -1;
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
    // TODO analisar bem esta, visto que é dentro de 1 loop:
    // devo trancar/destrancar a freeinode_ts iteração a iteração, ou trancar no início e só
    // destrancar nos returns? a inode_table só faz sentido trancar dentro do Finds first free entry
    // visto que só nessa única iteração é que é utilizada
    if (pthread_mutex_lock(&freeinode_ts_mutex) != 0) // placed here so that we don't lock/unlock every iteration
        return -1;
    for (int inumber = 0; inumber < INODE_TABLE_SIZE; inumber++) {
        if ((inumber * (int) sizeof(allocation_state_t) % BLOCK_SIZE) == 0) {
            insert_delay(); // simulate storage access delay (to freeinode_ts)
            // penso que este delay seja para simular que vamos buscar
            // à memória secundária 1 bloco referente à freeinode_ts
            // de cada vez. se (inumber * (int) sizeof(allocation_state_t) % BLOCK_SIZE) == 0
            // então é o início de 1 novo bloco (que depois fica guardado em cache)
            // o que não entendo é, tendo em conta que freeinode_ts é 1 array do tipo char,
            // porque é que usamos sizeof(allocation_state_t). eu pensava que os valores
            // FREE/TAKEN seriam auto convertidos para char ao fazer freeinode_ts[inumber] = FREE/TAKEN
        }
        /* Finds first free entry in i-node table */
        if (freeinode_ts[inumber] == FREE) {
            /* Found a free entry, so takes it for the new i-node*/
            freeinode_ts[inumber] = TAKEN;
            insert_delay(); // simulate storage access delay (to i-node)
            // CRITICAL SECTION START inode_table for writing
            inode_table[inumber].i_node_type = n_type;
            
            if (n_type == T_DIRECTORY) {
                /* Initializes directory (filling its block with empty
                 * entries, labeled with inumber==-1) */
                int b = data_block_alloc(); // obter 1 bloco de dados para o diretório
                if (b == -1) {
                    freeinode_ts[inumber] = FREE;
                    pthread_mutex_unlock(&freeinode_ts_mutex); // no need to check return value, we'll return an error anyway 
                    return -1; // neste caso não havia blocos de dados disponíveis
                }

                inode_table[inumber].i_size = BLOCK_SIZE; // um diretório (de momento) ocupa sempre 1 bloco completo
                inode_table[inumber].i_data_blocks[0] = b; // 'b' é o índice do bloco de dados deste diretório em fs_data

                // para facilitar o inode_delete estou a inicializá-los todos agora, assim em vez de verificar coisas com
                // inode.i_size para saber o nº de referências diretas simplesmente itero por todos, visto que são só 10 (11 a contar com o indireto)
                dir_entry_t *dir_entry = (dir_entry_t *)data_block_get(b);
                if (dir_entry == NULL) { // isto só acontece se b não for um índice válido, que é impossível neste caso
                    freeinode_ts[inumber] = FREE;
                    pthread_mutex_unlock(&freeinode_ts_mutex);
                    return -1;
                }
                if (pthread_mutex_unlock(&freeinode_ts_mutex) != 0)
                    return -1; // DUVIDA I'm not sure I like it like this, because then the inode is not properly initialized...
                // data_block_get devolve o endereço de 1 conjunto de bytes que vai até ao fim de fs_data (não está limitado ao tamanho de 1 bloco)
                // no entanto, não excedemos a leitura para lá de 1 bloco porque MAX_DIR_ENTRIES dá o nº de dir_entries num bloco
                // ao receber o void* e fazer o cast para dir_entry_t* podemos tratar esse conjunto de bytes como 1 ponteiro para 1 array de dir_entry_t
                for (size_t i = 0; i < MAX_DIR_ENTRIES; i++) { 
                    dir_entry[i].d_inumber = -1;
                }
            } else {
                if (pthread_mutex_unlock(&freeinode_ts_mutex) != 0)
                    return -1; // DUVIDA same one, inode not properly initialized. Maybe use the ret_code trick?
                /* In case of a new file, simply sets its size to 0 */
                inode_table[inumber].i_size = 0;
                inode_table[inumber].i_data_blocks[0] = -1;
            }
            // seja um diretório seja um ficheiro normal, inicializamos as referências para lá do primeiro bloco como nulas
            for (int block_number = 1; block_number < INODE_DIRECT_REFERENCES; block_number++)
                inode_table[inumber].i_data_blocks[block_number] = -1;
            inode_table[inumber].i_indirect_data_block = -1;
            // CRITICAL SECTION END inode_table for writing
            return inumber;
        }
    }
    pthread_mutex_unlock(&freeinode_ts_mutex);
    return -1;
}

/*
 * Deletes the i-node.
 * Input:
 *  - inumber: i-node's number
 * Returns: 0 if successful, -1 if failed
 * Note: when calling this function with a valid inumber, make sure it is protected by a write lock
 * on inode_table[inumber], as it writes over the inode (in inode_clear_file_contents)
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

    freeinode_ts[inumber] = FREE; // possivelmente passar isto para o fim da função, tenho medo que com o paralelismo 
                                  // eu liberte isto e depois ainda não limpei os data blocks e alguém escreve por cima: Update: desnecessário, ver Note
    int ret_code = 0;
    if (pthread_mutex_unlock(&freeinode_ts_mutex) != 0) 
        ret_code = -1; 
    if (inode_clear_file_contents(&inode_table[inumber] != 0)
        ret_code = -1;
    return ret_code;
}

// Note there might be an off by one problem here: if file_offset is BLOCK_SIZE this will return 1, however block 1 will not be allocated if
// the size of the file is also BLOCK_SIZE, this is ok for all writes and reads where we have checked if the block exists, but if it's being
// used to delete blocks caution is advised
static inline int calculate_block_index(size_t file_offset) {
    return (int) file_offset / BLOCK_SIZE; // naughty cast. All casts signaled naughty are due to the original use of an int for block number
}
// Functions related to data blocks are static 
// because files outside of state.c don't deal with data blocks (TODO: ask if all this is ok)
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
    // the reason for the -1 is that if for example inode->i_size == BLOCK_SIZE, calculate_block_index will
    // return 1, but the block with block_ix 1 isn't allocated. This would create a problem (without the -1) everytime
    // inode->i_size % BLOCK_SIZE == 0 (inode->i_size points to beginning of a block). With the -1, the problem is solved, 
    // and if the inode->i_size didn't point to the beginning of a block there will be no problem either way. Note that because of the
    // required check that the indirect block is in use, inode->i_size -1 is always greater than 0
    int final_block_ix = calculate_block_index(i_size-1);

    final_block_ix -= INODE_DIRECT_REFERENCES; // now final_block_ix stores the index of the last block in the indirect block, and not the whole file

    // now we need to get the data from the indirect block. We treat it as an array of integers, since
    // we're using integers to index blocks, as per the original code
    int *indirect_block_data = (int*) data_block_get(indirect_block_number);

    if (!indirect_block_data) // an error ocurred
        return -1;
    
    int ret_code = data_block_free(indirect_block_number); // if an error ocurred but we still received data
    // from data_block_get it is very weird because the verification is the same. I decided to assume that the
    // data is valid, and that it might contain references to blocks that need to be freed, but I still return
    // the error to the calling function

    // this cleans all the data blocks referenced by the indirect block. block_index is the index in indirect_block_data
    // the actual block number is stored in indirect_block_data[block_index]
    for (int block_index = 0; block_index <= final_block_ix; block_index++) {
        if (data_block_free(indirect_block_data[block_index]) == -1) {
            ret_code = -1; // applying the same strategy of not returning while there might still be data to clean
        }
    }
    
    return ret_code;
}


int inode_clear_file_contents(inode_t *inode) {
    int ret_code = 0; // return value
    if (inode->i_size == 0) // the file was empty, nothing to do
        return 0;

    // free direct blocks
    for (int block_number = 0; block_number < INODE_DIRECT_REFERENCES; block_number++) {
        // this will iterate over blocks that may not be used, but probably is fast enough that it doesn't matter
        if (inode->i_data_blocks[block_number] != -1 && data_block_free(inode->i_data_blocks[block_number]) == -1) {
            ret_code = -1; // this way, if we need to free more blocks we can do it and still return an error referring to this block
        }
    }
    
    // maybe I shouldn't do this verification here, and do it directly in free_indirect_block
    if (inode->i_indirect_data_block != -1 && free_indirect_block(inode->i_indirect_data_block, inode->i_size) == -1) {
        ret_code = -1;
    }
    
    inode->i_size = 0;
   
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
    return indirect_block_data[block_ix]; // here is where we might touch unitialised memory
}

static int allocate_new_block_for_writing(int block_ix, inode_t *inode, int **indirect_block_data) {
    int block_number = -1;
    if (block_ix < INODE_DIRECT_REFERENCES) { // here we allocate a new direct block
        inode->i_data_blocks[block_ix] = data_block_alloc(); // if this fails it will just store -1 there, which is ok because it's the value that's supposed to be there
        block_number = inode->i_data_blocks[block_ix]; // if this -1 the error will be signalled when we return -1
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

// o openfile->of_offset não será atualizado nesta função, ela
// vai lidar apenas com a escrita no inode. Idem aspas para inode_read
ssize_t inode_write(inode_t *inode, void const *buffer, size_t to_write, size_t file_offset) {
    if (file_offset > inode->i_size) // in this case we are trying to make a "hole" in the file, writing past its end
        return -1;
    if (file_offset + to_write > MAX_FILE_SIZE)  
        to_write = MAX_FILE_SIZE - file_offset;
    if (to_write == 0) 
       return 0;

    ssize_t bytes_written = 0;
    int first_block_ix = calculate_block_index(file_offset); 
    int last_block_ix = calculate_block_index(file_offset + to_write);
    size_t block_offset = calculate_block_offset(file_offset); // offset in the block we are currently reading from, which right now is first_block
    int block_number = -1;
    void *block = NULL;
    int *indirect_block_data = NULL;
    if (last_block_ix >= INODE_DIRECT_REFERENCES) {
        indirect_block_data = (int*) data_block_get(inode->i_indirect_data_block);  // check for errors inside the loop
    }
    size_t to_write_in_block; 

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
        bytes_written += (ssize_t) to_write_in_block;
        file_offset += to_write_in_block;
        buffer += to_write_in_block;
        to_write -= to_write_in_block;
        block_offset = 0; // offset is possibly not 0 in the first iteration, but in the other ones it's definitely 0
        if (file_offset > inode->i_size)
            inode->i_size = file_offset;
    }
    
    if (bytes_written == 0) // if bytes_written is 0 at this point there was an error before we could write anything
        return -1;

    return bytes_written; 
}

ssize_t inode_read(inode_t *inode, void *buffer, size_t to_read, size_t file_offset) {
    if (file_offset > inode->i_size) // this might happen if someone in another thread truncates the file between someone else calling this function and the start of its execution
        return -1;                   // for this to actually work properly I once thought that everytime we want to access a data block we need to make sure it exists. I believe that it might
                                     // work like this, because of the lock of the inode when we call this function in operations.c and the checks on the original code (valid functions)
    size_t available_bytes = inode->i_size - file_offset;
    if (to_read > available_bytes)
        to_read = available_bytes;
    if (to_read == 0)
        return 0;

    ssize_t bytes_read = 0;
    int first_block_ix = calculate_block_index(file_offset); // index of the first block from which we will be reading
    int last_block_ix = calculate_block_index(file_offset + to_read); // index of the last block from which we will be reading
    size_t block_offset = calculate_block_offset(file_offset); // offset in the block we are currently reading from, which right now is first_block
    int block_number = -1;
    void *block = NULL;
    int *indirect_block_data = NULL;
    if (last_block_ix >= INODE_DIRECT_REFERENCES) 
        indirect_block_data = (int*) data_block_get(inode->i_indirect_data_block); // we check for errors later, inside the loop
        // The reasoning is that it's just an if statement so it's probably ok to check inside the loop (no accesses to memory or slow operations)
        // and this way it allows for the possibility to read bytes that come from direct blocks before crashing without adding lots of lines of code

    size_t to_read_from_block; // number of bytes to be read from the current block 
    
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
        bytes_read += (ssize_t) to_read_from_block;
        buffer += to_read_from_block;
        to_read -= to_read_from_block;
        block_offset = 0; // offset is possibly not 0 in the first iteration, but in the other ones it's definitely 0
    }
    
    // in this case there was an error, either getting the block number or getting the data block itself
    // the choice was to return the bytes read if we had read any bytes before the error, and return the error
    // if not. The if statement is true if there is an error and we hadn't read any bytes before the error
    if (bytes_read == 0) 
        return -1;

    return bytes_read; 
}


/*
 * Returns a pointer to an existing i-node.
 * Input:
 *  - inumber: identifier of the i-node
 * Returns: pointer if successful, NULL if failed
 * Note: as of right now inode_table's entries are not initialized in the beginning to a dummy value that indicates invalidness, nor
 * properly signalled as destroyed with such a value  when inode_delete is called (this is because the original code did neither of these things). 
 * As such there might be bugs wherein the inumber is valid but it was never initialized (so we will be accessing unitialized memory on the stack)
 * or it was once initialized but now has the values that inode_delete left there. This is not very good defensive programming, I believe I should
 * such a dummy value and if the value is the dummy return NULL
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

    insert_delay(); // simulate storage access delay to i-node with inumber
    // CRITICAL SECTION START read inode_table
    if (inode_table[inumber].i_node_type != T_DIRECTORY) {
        // CRITICAL SECTION END read inode_table
        return -1;
    }

    if (strlen(sub_name) == 0) {
        return -1;
    }

    /* Locates the block containing the directory's entries */
    dir_entry_t *dir_entry =
        (dir_entry_t *)data_block_get(inode_table[inumber].i_data_blocks[0]);
    // CRITICAL SECTION END read inode_table, if we are protecting data blocks (which we aren't)
    // so the end is really at the end of the function, where we end the dependency on the data block
    if (dir_entry == NULL) {
        return -1;
    }

    /* Finds and fills the first empty entry */
    for (size_t i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (dir_entry[i].d_inumber == -1) {
            dir_entry[i].d_inumber = sub_inumber;
            strncpy(dir_entry[i].d_name, sub_name, MAX_FILE_NAME - 1);
            dir_entry[i].d_name[MAX_FILE_NAME - 1] = 0;
            return 0;
        }
    }

    return -1; // there was no space for another entry in the directory
}

/* Looks for a given name inside a directory
 * Input:
 * 	- parent directory's i-node number
 * 	- name to search
 * 	Returns i-number linked to the target name, -1 if not found
 */
int find_in_dir(int inumber, char const *sub_name) { 
    insert_delay(); // simulate storage access delay to i-node with inumber
    // CRITICAL SECTION START read inode_table 
    // this function is not part of the public API and it is only called
    // in operations.c inside tfs_lookup, where it is always protected by the mutex of the 
    // root file placed in tfs_write. As such the whole function is covered by a mutex
    // the critical sections are still highlighted, because maybe (in the exam perhaps)
    // this might have to change, with multiple directories for example, and then this
    // function won't be MT safe
    if (!valid_inumber(inumber) ||
        inode_table[inumber].i_node_type != T_DIRECTORY) {
        // CRITICAL SECTION END inode_table
        return -1;
    }

    /* Locates the block containing the directory's entries */
    dir_entry_t *dir_entry =
        (dir_entry_t *)data_block_get(inode_table[inumber].i_data_blocks[0]);
    // CRITICAL SECTION END inode_table this is wrong! it is only 
    // the end of the critical section if we protect the data block: since we don't
    // the critical section ends when we stop using the data block's data
    if (dir_entry == NULL) {
        return -1;
    }

    /* Iterates over the directory entries looking for one that has the target
     * name */
    for (int i = 0; i < MAX_DIR_ENTRIES; i++)
        if ((dir_entry[i].d_inumber != -1) &&
            (strncmp(dir_entry[i].d_name, sub_name, MAX_FILE_NAME) == 0)) {
            return dir_entry[i].d_inumber;
        }

    return -1;
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
                free_blocks[i] = FREE; // this is just so that the block doesn't stay forever TAKEN, but I don't know if it makes sense DUVIDA
                return -1;
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
 * Returns: file handle if successful, -1 otherwise
 */
int add_to_open_file_table(int inumber, size_t offset) {
    if (pthread_mutex_lock(&free_open_file_entries_mutex) != 0)
        return -1;
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (free_open_file_entries[i] == FREE) {
            free_open_file_entries[i] = TAKEN;
            if (pthread_mutex_unlock(&free_open_file_entries_mutex) != 0) {
                free_open_file_entries[i] = TAKEN; // DUVIDA posso fazer isto para nao ficar sempre TAKEN
                return -1;
            }
            open_file_table[i].of_inumber = inumber;
            open_file_table[i].of_offset = offset;
            return i;
        }
    }
    pthread_mutex_unlock(&free_open_file_entries_mutex);
    return -1;
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
    free_open_file_entries[fhandle] = FREE;
    if (pthread_mutex_unlock(&free_open_file_entries_mutex) != 0)
        return -1;
    return 0;
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
