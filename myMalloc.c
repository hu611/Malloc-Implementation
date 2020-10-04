#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "myMalloc.h"
#include "printing.h"

/* Due to the way assert() prints error messges we use out own assert function
 * for deteminism when testing assertions
 */
#ifdef TEST_ASSERT
  inline static void assert(int e) {
    if (!e) {
      const char * msg = "Assertion Failed!\n";
      write(2, msg, strlen(msg));
      exit(1);
    }
  }
#else
  #include <assert.h>
#endif

/*
 * Mutex to ensure thread safety for the freelist
 */
static pthread_mutex_t mutex;

/*
 * Array of sentinel nodes for the freelists
 */
header freelistSentinels[N_LISTS];

/*
 * Pointer to the second fencepost in the most recently allocated chunk from
 * the OS. Used for coalescing chunks
 */
header * lastFencePost;

/*
 * Pointer to maintian the base of the heap to allow printing based on the
 * distance from the base of the heap
 */ 
void * base;

/*
 * List of chunks allocated by  the OS for printing boundary tags
 */
header * osChunkList [MAX_OS_CHUNKS];
size_t numOsChunks = 0;

/*
 * direct the compiler to run the init function before running main
 * this allows initialization of required globals
 */
static void init (void) __attribute__ ((constructor));

// Helper functions for manipulating pointers to headers
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off);
static inline header * get_left_header(header * h);
static inline header * ptr_to_header(void * p);

// Helper functions for allocating more memory from the OS
static inline void initialize_fencepost(header * fp, size_t left_size);
static inline void insert_os_chunk(header * hdr);
static inline void insert_fenceposts(void * raw_mem, size_t size);
static header * allocate_chunk(size_t size);

// Helper functions for freeing a block
static inline void deallocate_object(void * p);

// Helper functions for allocating a block
static inline header * allocate_object(size_t raw_size);

// Helper functions for verifying that the data structures are structurally 
// valid
static inline header * detect_cycles();
static inline header * verify_pointers();
static inline bool verify_freelist();
static inline header * verify_chunk(header * chunk);
static inline bool verify_tags();
static header * split(header * leftheader,size_t size);
static void init();
int getindex(size_t size);
static bool isMallocInitialized;

/**
 * @brief Helper function to retrieve a header pointer from a pointer and an 
 *        offset
 *
 * @param ptr base pointer
 * @param off number of bytes from base pointer where header is located
 *
 * @return a pointer to a header offset bytes from pointer
 */
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off) {
	return (header *)((char *) ptr + off);
}

/**
 * @brief Helper function to get the header to the right of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
header * get_right_header(header * h) {
	return get_header_from_offset(h, get_block_size(h));
}

/**
 * @brief Helper function to get the header to the left of //a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
inline static header * get_left_header(header * h) {
  return get_header_from_offset(h, -h->left_size);
}

/**
 * @brief Fenceposts are marked as always allocated and may need to have
 * a left object size to ensure coalescing happens properly
 *
 * @param fp a pointer to the header being used as a fencepost
 * @param left_size the size of the object to the left of the fencepost
 */
inline static void initialize_fencepost(header * fp, size_t left_size) {
	set_block_state(fp,FENCEPOST);
	set_block_size(fp, ALLOC_HEADER_SIZE);
	fp->left_size = left_size;
}

/**
 * @brief Helper function to maintain list of chunks from the OS for debugging
 *
 * @param hdr the first fencepost in the chunk allocated by the OS
 */
inline static void insert_os_chunk(header * hdr) {
  if (numOsChunks < MAX_OS_CHUNKS) {
    osChunkList[numOsChunks++] = hdr;
  }
}

/**
 * @brief given a chunk of memory insert fenceposts at the left and 
 * right boundaries of the block to prevent coalescing outside of the
 * block
 *
 * @param raw_mem a void pointer to the memory chunk to initialize
 * @param size the size of the allocated chunk
 */
inline static void insert_fenceposts(void * raw_mem, size_t size) {
  // Convert to char * before performing operations
  char * mem = (char *) raw_mem;

  // Insert a fencepost at the left edge of the block
  header * leftFencePost = (header *) mem;
  initialize_fencepost(leftFencePost, ALLOC_HEADER_SIZE);

  // Insert a fencepost at the right edge of the block
  header * rightFencePost = get_header_from_offset(mem, size - ALLOC_HEADER_SIZE);
  initialize_fencepost(rightFencePost, size - 2 * ALLOC_HEADER_SIZE);
}

/**
 * @brief Allocate another chunk from the OS and prepare to insert it
 * into the free list
 *
 * @param size The size to allocate from the OS
 *
 * @return A pointer to the allocable block in the chunk (just after the 
 * first fencpost)
 */
static header * allocate_chunk(size_t size) {
  void * mem = sbrk(size);
  
  insert_fenceposts(mem, size);
  header * hdr = (header *) ((char *)mem + ALLOC_HEADER_SIZE);
  set_block_state(hdr, UNALLOCATED);
  set_block_size(hdr, size - 2 * ALLOC_HEADER_SIZE);
  hdr->left_size = ALLOC_HEADER_SIZE;
  return hdr;
}

/**
 * @brief Helper allocate an object given a raw request size from the user
 *
 * @param raw_size number of bytes the user needs
 *
 * @return A block satisfying the user's request
 */
static inline header * allocate_object(size_t raw_size) {
  // TODO implement allocation
  if(raw_size == 0) {
	return NULL;
  }
  // calculate the block size
  int roundsize = 0;
  header * finalblock = NULL;
  //round up the size of requested size
  if(raw_size % 8 == 0) {
	  roundsize = raw_size;
  } else {
	  roundsize = raw_size/8;
	  roundsize++;
	  roundsize = roundsize * 8;
  }
  if(raw_size <= 16) {
	roundsize = 16;
  }
  //roundsize + 16(metadata)
  int totalsize = roundsize + 2 * sizeof(size_t);
  // find the appropriate free list
  int freelistindex = getindex(totalsize);
  header* currentheader = &freelistSentinels[freelistindex];
  //true or false variable and 0 stands for currentheader is null)
  int tof = 0;
  //check if the block is the exact size
  int exactsize = 0;
  if(currentheader->next != currentheader) {
	tof = 1;
	exactsize = 1;
	finalblock = currentheader->next;
  }
//check the next list until there is a block, which can satisfy the request
  while(tof == 0 && freelistindex != N_LISTS - 2) {
	freelistindex = freelistindex + 1;
	currentheader = &freelistSentinels[freelistindex];
	if(currentheader->next != currentheader) {
		if(get_block_size(currentheader->next) - totalsize >= sizeof(header)) {
			finalblock = split(currentheader->next,totalsize);
		} else{
			finalblock = currentheader->next;
		}
		tof = 1;
	}
  }
  freelistindex = freelistindex + 1;
  //if it is the last index of freelist
  if(freelistindex == N_LISTS - 1) {
	  //boolean variable to check if the block has been found
	  int find = 0;
	  header * lastindexhdr = &freelistSentinels[N_LISTS - 1];
	  //traverse through last index of freelist
	  while(lastindexhdr->next != &freelistSentinels[N_LISTS-1] && find == 0) {
		  lastindexhdr = lastindexhdr->next;
		  size_t lastindexblocksize = get_block_size(lastindexhdr);
		  //if the block from last index satisfy user's request
		  if(lastindexblocksize >= totalsize && lastindexblocksize < totalsize + sizeof(header)) {
			  find = 1;
			  finalblock = lastindexhdr;
		  } else if(lastindexblocksize > totalsize && lastindexblocksize >= totalsize + sizeof(header)) {
		  	find = 1;
			finalblock = split(lastindexhdr,totalsize);
		  }
	  }
  }
  if(finalblock != null) {
	  finalblock->next->prev = finalblock->prev;
	  finalblock->prev->next = finalblock->next;
	  finalblock->next = NULL;
	  finalblock->prev = NULL;
  }
	  set_block_state(finalblock,ALLOCATED);
	  return finalblock->data;

  
  
  //(void)raw_size;
  //assert(false);
  //exit(1);
}

int getindex(size_t size) {
	int index = size/8 - 3;
	if(index > N_LISTS -1) {
		index = N_LISTS - 1;
	}
	return index;
}
//split function which split the block
static header * split(header * leftheader,size_t size) {
	int remaining_size = get_block_size(leftheader) - size;
	int indexforremaining = getindex(remaining_size);
	int originalindex = getindex(get_block_size(leftheader));
	header * newheader = get_header_from_offset(leftheader,get_block_size(leftheader)-size);
	//Initialize the size and state of the new header and update the size of original header
	set_block_size_and_state(newheader,size,UNALLOCATED);
	set_block_size(leftheader,get_block_size(leftheader)-size);
	//update the left size variable
	newheader->left_size = get_block_size(leftheader);
	get_right_header(newheader)->left_size = size;
	//update left header's prev and next
	if(originalindex == indexforremaining) {
	leftheader->next->prev = leftheader->prev;
	leftheader->prev->next = leftheader->next;
	leftheader->next = freelistSentinels[indexforremaining].next;
	leftheader->prev = &freelistSentinels[indexforremaining];
	freelistSentinels[indexforremaining].next->prev = leftheader;
	freelistSentinels[indexforremaining].next = leftheader;
	}
	int index_for_new = getindex(size);
	//insert newheader into freelist
	newheader->next = freelistSentinels[index_for_new].next;
	newheader->prev = &freelistSentinels[index_for_new];	
	newheader->next->prev = newheader;
	newheader->prev->next = newheader;
	return newheader;
}

/**
 * @brief Helper to get the header from a pointer allocated with malloc
 *
 * @param p pointer to the data region of the block
 *
 * @return A pointer to the header of the block
 */
static inline header * ptr_to_header(void * p) {
  return (header *)((char *) p - ALLOC_HEADER_SIZE); //sizeof(header));
}

/**
 * @brief Helper to manage deallocation of a pointer returned by the user
 *
 * @param p The pointer returned to the user by a call to malloc
 */
static inline void deallocate_object(void * p) {
	if(p == NULL) {
		return;
	}
	header * freeheader = ptr_to_header(p);
	header * leftheader = get_left_header(freeheader);
	header * rightheader = get_right_header(freeheader);
	if(get_block_state(freeheader) != ALLOCATED) {
		printf("Double Free Detected\n");
		assert(0);
	}
	set_block_state(freeheader,UNALLOCATED);
	//if left header and right header are both allocated
	if(get_block_state(leftheader) != UNALLOCATED && get_block_state(rightheader) != UNALLOCATED) {
		int index = getindex(get_block_size(freeheader));
		freeheader->prev = &freelistSentinels[index];
		freeheader->next = freelistSentinels[index].next;
		freelistSentinels[index].next = freeheader;
		freeheader->next->prev = freeheader;
	} else if(get_block_state(rightheader) == UNALLOCATED && get_block_state(leftheader) != UNALLOCATED) {
		int rightindex = getindex(get_block_size(rightheader));
		set_block_size(freeheader,get_block_size(freeheader)+get_block_size(rightheader));
		//reset the left size variable of right right header
		get_right_header(rightheader)->left_size = get_block_size(freeheader);
		int currentindex = getindex(get_block_size(freeheader));
		//if the index changes, need to remove right header and insert the new header
		if(currentindex != rightindex) {
			rightheader->next->prev = rightheader->prev;
			rightheader->prev->next = rightheader->next;
			rightheader->prev = NULL;
			rightheader->next = NULL;
			freeheader->prev = &freelistSentinels[currentindex];
			freeheader->next = freelistSentinels[currentindex].next;
			freeheader->next->prev = freeheader;
			freeheader->prev->next = freeheader;
		}else{
			//if they are in the last index of freelist, then need to assign rightheader's next,prev to newheader
			freeheader->next = rightheader->next;
			freeheader->prev = rightheader->prev;
			freeheader->next->prev = freeheader;
			freeheader->prev->next = freeheader;
			rightheader->next = NULL;
			rightheader->prev = NULL;
		}
	} else if(get_block_state(rightheader) != UNALLOCATED && get_block_state(leftheader) == UNALLOCATED) {
		int leftindex = getindex(get_block_size(leftheader));
		set_block_size(leftheader,get_block_size(leftheader)+get_block_size(freeheader));
		//reset right header's left_size
		get_right_header(freeheader)->left_size = get_block_size(leftheader);
		int currentindex = getindex(get_block_size(leftheader));
		if(currentindex != leftindex) {
			leftheader->next->prev = leftheader->prev;
			leftheader->prev->next = leftheader->next;
			leftheader->prev = &freelistSentinels[currentindex];
			leftheader->next = freelistSentinels[currentindex].next;
			leftheader->prev->next = leftheader;
			leftheader->next->prev = leftheader;
		}
	} else if(get_block_state(rightheader) == ALLOCATED && get_block_state(leftheader) == ALLOCATED){
		//when both left and right are unallocated
		int leftindex = getindex(get_block_size(leftheader));
		set_block_size(leftheader,get_block_size(leftheader)+get_block_size(freeheader)+get_block_size(rightheader));
		get_right_header(rightheader)->left_size = get_block_size(leftheader);
		int currentindex = getindex(get_block_size(leftheader));
		rightheader->next->prev = rightheader->prev;
		rightheader->prev->next = rightheader->next;
		if(currentindex != leftindex) {
			leftheader->next->prev = leftheader->prev;
			leftheader->prev->next = leftheader->next;
			leftheader->prev = &freelistSentinels[currentindex];
			leftheader->next = freelistSentinels[currentindex].next;
			leftheader->prev->next = leftheader;
			leftheader->next->prev = leftheader;
		}
	}
  // TODO implement deallocation
 // (void) p;
 // assert(false);
 // exit(1);
}

/**
 * @brief Helper to detect cycles in the free list
 * https://en.wikipedia.org/wiki/Cycle_detection#Floyd's_Tortoise_and_Hare
 *
 * @return One of the nodes in the cycle or NULL if no cycle is present
 */
static inline header * detect_cycles() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * slow = freelist->next, * fast = freelist->next->next; 
         fast != freelist; 
         slow = slow->next, fast = fast->next->next) {
      if (slow == fast) {
        return slow;
      }
    }
  }
  return NULL;
}

/**
 * @brief Helper to verify that there are no unlinked previous or next pointers
 *        in the free list
 *
 * @return A node whose previous and next pointers are incorrect or NULL if no
 *         such node exists
 */
static inline header * verify_pointers() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * cur = freelist->next; cur != freelist; cur = cur->next) {
      if (cur->next->prev != cur || cur->prev->next != cur) {
        return cur;
      }
    }
  }
  return NULL;
}

/**
 * @brief Verify the structure of the free list is correct by checkin for 
 *        cycles and misdirected pointers
 *
 * @return true if the list is valid
 */
static inline bool verify_freelist() {
  header * cycle = detect_cycles();
  if (cycle != NULL) {
    fprintf(stderr, "Cycle Detected\n");
    print_sublist(print_object, cycle->next, cycle);
    return false;
  }

  header * invalid = verify_pointers();
  if (invalid != NULL) {
    fprintf(stderr, "Invalid pointers\n");
    print_object(invalid);
    return false;
  }

  return true;
}

/**
 * @brief Helper to verify that the sizes in a chunk from the OS are correct
 *        and that allocated node's canary values are correct
 *
 * @param chunk AREA_SIZE chunk allocated from the OS
 *
 * @return a pointer to an invalid header or NULL if all header's are valid
 */
static inline header * verify_chunk(header * chunk) {
	if (get_block_state(chunk) != FENCEPOST) {
		fprintf(stderr, "Invalid fencepost\n");
		print_object(chunk);
		return chunk;
	}
	
	for (; get_block_state(chunk) != FENCEPOST; chunk = get_right_header(chunk)) {
		if (get_block_size(chunk)  != get_right_header(chunk)->left_size) {
			fprintf(stderr, "Invalid sizes\n");
			print_object(chunk);
			return chunk;
		}
	}
	
	return NULL;
}

/**
 * @brief For each chunk allocated by the OS verify that the boundary tags
 *        are consistent
 *
 * @return true if the boundary tags are valid
 */
static inline bool verify_tags() {
  for (size_t i = 0; i < numOsChunks; i++) {
    header * invalid = verify_chunk(osChunkList[i]);
    if (invalid != NULL) {
      return invalid;
    }
  }

  return NULL;
}

/**
 * @brief Initialize mutex lock and prepare an initial chunk of memory for allocation
 */
static void init() {
  // Initialize mutex for thread safety
  pthread_mutex_init(&mutex, NULL);

#ifdef DEBUG
  // Manually set printf buffer so it won't call malloc when debugging the allocator
  setvbuf(stdout, NULL, _IONBF, 0);
#endif // DEBUG

  // Allocate the first chunk from the OS
  header * block = allocate_chunk(ARENA_SIZE);

  header * prevFencePost = get_header_from_offset(block, -ALLOC_HEADER_SIZE);
  insert_os_chunk(prevFencePost);

  lastFencePost = get_header_from_offset(block, get_block_size(block));

  // Set the base pointer to the beginning of the first fencepost in the first
  // chunk from the OS
  base = ((char *) block) - ALLOC_HEADER_SIZE; //sizeof(header);

  // Initialize freelist sentinels
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    freelist->next = freelist;
    freelist->prev = freelist;
  }

  // Insert first chunk into the free list
  header * freelist = &freelistSentinels[N_LISTS - 1];
  freelist->next = block;
  freelist->prev = block;
  block->next = freelist;
  block->prev = freelist;
}

/* 
 * External interface
 */
void * my_malloc(size_t size) {
  pthread_mutex_lock(&mutex);
  header * hdr = allocate_object(size); 
  pthread_mutex_unlock(&mutex);
  return hdr;
}

void * my_calloc(size_t nmemb, size_t size) {
  return memset(my_malloc(size * nmemb), 0, size * nmemb);
}

void * my_realloc(void * ptr, size_t size) {
  void * mem = my_malloc(size);
  memcpy(mem, ptr, size);
  my_free(ptr);
  return mem; 
}

void my_free(void * p) {
  pthread_mutex_lock(&mutex);
  deallocate_object(p);
  pthread_mutex_unlock(&mutex);
}

bool verify() {
  return verify_freelist() && verify_tags();
}
