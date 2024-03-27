// SPDX-License-Identifier: BSD-3-Clause

#include <osmem.h>
#include <assert.h>
#include <sys/mman.h>
#include <string.h>
#define ALIGNMENT 8 // must be a power of 2
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define HEADER_SIZE (ALIGN(sizeof(block_header)))
#define MAP_ANONYMOUS 0x20
#define MMAP_THRESHOLD 131072
#define PAGE_SIZE 4096
#define MIN_BLOCK_SIZE (ALIGN(1) + HEADER_SIZE)

// header = struct block meta si are 28 bytes dar e aliniat la 32
//  IMPLICIT LIST STRATEGY

block_header *head; // the head of the free list
int heap_inited; //implicit 0
void insert_End_list(block_header *newblock)
{
	// if the linked list is empty, make the newblock as head
	if (head == NULL) {
		head = newblock;
		head->size = newblock->size;
		head->status = newblock->status;
		head->prev = NULL;
		head->next = NULL;
		return;
	}
	// if the linked list is not empty, traverse to the end of the linked list
	block_header *aux = head;

	while (aux->next != NULL)
		aux = aux->next;
	// now, the last node of the linked list is aux
	// point the next of the last node (aux) to newblock.
	aux->next = newblock;
	newblock->prev = aux;
	newblock->next = NULL;
}

void split_block(block_header *block, size_t needed)
{
	if (block->size - needed >= MIN_BLOCK_SIZE) { // block_meta structure and at least 1 byte of usable memory
		block_header *newblock = (block_header *)((char *)block + needed + HEADER_SIZE);
		size_t remaining = block->size - needed - HEADER_SIZE;

		newblock->size = remaining;
		newblock->status = STATUS_FREE;
		block->size = needed;
		block->status = STATUS_ALLOC;
		// lista arata asa acum:  block <---> newblock
		if (!head) {
			head = block;
			newblock->next = NULL;
			newblock->prev = head;
			head->next = newblock;
			head->prev = NULL;
		} else { // insert
			newblock->next = block->next;
			newblock->prev = block;
			if (block->next)
				block->next->prev = newblock;
			block->next = newblock;
		}
	}
}

// Note: For consistent results, coalesce all adjacent free blocks before searching.
void *find_best_fit(size_t size)
{
	block_header *best_fitting_block = NULL,
				 *current = head;
	while (current != NULL) {
		if (current->status == STATUS_FREE && current->size == size) {
			best_fitting_block = current;
			best_fitting_block->size = current->size;
			break;
		}
		if (current->status == STATUS_FREE && current->size > size)
			if (best_fitting_block == NULL || best_fitting_block->size >= current->size) {
				best_fitting_block = current;
				best_fitting_block->size = current->size;
			}
		current = current->next;
	}
	if (best_fitting_block == NULL)
		return NULL;
	split_block(best_fitting_block, size);
	best_fitting_block->status = STATUS_ALLOC;
	return best_fitting_block;
	return NULL;
}

// free block not found; request space from the OS using sbrk and add the new block to the end of the list
block_header *request_space(size_t size)
{
	block_header *new_block;

	new_block = (block_header *)sbrk(ALIGN(size + HEADER_SIZE));
	if ((void *)new_block == (void *)-1)
		return NULL; // sbrk failed
	new_block->size = size;
	new_block->status = STATUS_ALLOC;
	return new_block;
}

block_header *get_last_block(void)
{
	if (!head)
		return NULL;
	block_header *current = head;

	while (current->next != NULL)
		current = current->next;
	return current;
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if (size <= 0)
		return NULL;
	size_t newsize = ALIGN(size);
	size_t fullsize = ALIGN(size + HEADER_SIZE);
	block_header *block;

	if (heap_inited == 0) {
		// HEAP PREALLOCATION
		if (size >= MMAP_THRESHOLD) {
			block = (block_header *)mmap(NULL, fullsize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			if ((void *)block == (void *)-1)
				return NULL;
			block->size = newsize;
			block->status = STATUS_MAPPED;
			// heap_inited = 1;
			insert_End_list(block);
			return (char *)block + HEADER_SIZE;
		}
		//else
		// prealocam 128kB din buzunarul nostru generos
		block_header *new_block = (block_header *)sbrk(MMAP_THRESHOLD);

		if ((void *)new_block == (void *)-1)
			return NULL; // sbrk failed
		new_block->size = MMAP_THRESHOLD - HEADER_SIZE;
		new_block->status = STATUS_ALLOC;
		insert_End_list(new_block);
		split_block(new_block, newsize); // split are deja insert bagata in el
		heap_inited = 1;
		return (char *)new_block + HEADER_SIZE;
	}
	// NO HEAP PREALLOCATION
	// SEE IF BIG CHUNK OR SMALL CHUNK
	if (fullsize >= MMAP_THRESHOLD) {
		// BIG CHUNK - MMAP()
		block = (block_header *)mmap(NULL, fullsize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if ((void *)block == (void *)-1)
			return NULL;
		block->size = newsize;
		block->status = STATUS_MAPPED;
		insert_End_list(block);
		return (char *)block + HEADER_SIZE;
	}
	//else
	// SMALL CHUNK - BRK()
	if (head == NULL) {
		// First call
		block = request_space(newsize);
		if (!block)
			return NULL;
		//else
		insert_End_list(block);
	} else {
		// list is not empty
		// SEE IF EXPAND OR NOT
		block = find_best_fit(newsize); // are deja split care are insert
		if (block == NULL) {
			// oh no - nu avem spatiu, trb sa alocam
			// check if expand
			block_header *last_block = get_last_block();

			if (last_block->status == STATUS_FREE) {
				// expand
				void *ptr = sbrk(newsize - last_block->size);

				if (ptr == (void *)-1)
					return NULL;
				last_block->status = STATUS_ALLOC;
				last_block->size = newsize;
				last_block->next = NULL;
				return (char *)last_block + HEADER_SIZE;
			}
			//else
			// cannot expand
			block = sbrk(fullsize);
			if ((void *)block == (void *)-1)
				return NULL;
			//else
			block->size = newsize;
			block->status = STATUS_ALLOC;
			insert_End_list(block);
		} else {
			// yay, am gasit spatiu in lista
			block->status = STATUS_ALLOC;
		}
	}
	return (char *)block + HEADER_SIZE;
}

block_header *get_block_ptr(void *ptr)
{
	return (block_header *)ptr - 1;
}

void expand_block(block_header *start_block)
{
	if (!head)
		return;
	assert(start_block->status != STATUS_FREE);
	block_header *block = start_block ? start_block : head;

	while (block != NULL && block->next != NULL) {
		block_header *block_next = block->next;

		if (block_next->status == STATUS_FREE) {
			block->size += block_next->size + HEADER_SIZE;
			if (block_next->next != NULL)
				block_next->next->prev = block;
			block->next = block_next->next;
		} else {
			break;
	}}
}

void coalesce_immediate(block_header *block)
{
	if (block->status != STATUS_FREE)
		return;
	block_header *block_next = NULL, *block_prev = NULL;

	if (block->prev != NULL)
		if (block->prev->status == STATUS_FREE)
			block_prev = block->prev;
	if (block->next != NULL)
		if (block->next->status == STATUS_FREE)
			block_next = block->next;
	if (block_prev && block_next) {
		block_prev->size += block->size + block_next->size + 2 * HEADER_SIZE;
		block_prev->next = block_next->next;
		if (block_next->next != NULL)
			block_next->next->prev = block_prev;
	} else {
		if (block_prev && !block_next) {
			block_prev->size += block->size + HEADER_SIZE;
			block_prev->next = block->next;
			if (block->next != NULL)
				block->next->prev = block_prev;
	} else {
		if (!block_prev && block_next) {
			block->size += block_next->size;
			block->next = block_next->next;
			if (block_next->next != NULL)
				block_next->next->prev = block;
	}
}}}

void remove_block_from_list(block_header *block)
{ // Vrem sa stergem din lista un bloc pt care facem munmap
	if (head == block) {
		head = head->next;
		if (head != NULL) {
			head->prev = NULL;
			return;
		}
	} else {
		if (block->prev)
			block->prev->next = block->next;
		if (block->next)
			block->next->prev = block->prev;
	}
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (ptr == NULL)
		return;
	block_header *block = get_block_ptr(ptr);

	assert(block->status == STATUS_ALLOC || block->status == STATUS_MAPPED);
	if (block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;
		coalesce_immediate(block);
	} else {
		if (block->status == STATUS_MAPPED) {
			remove_block_from_list(block);
			munmap(block, block->size + HEADER_SIZE);
	}
}
}

int is_last_block(block_header *block)
{
	// verifici daca blocul e ULTIMUL DE PE HEAP (nici macar free sa nu aiba dupa el)
	block_header *next_block = block->next;
	int ok = 1;

	if (block->status == STATUS_ALLOC)
		while (ok && next_block != NULL && (next_block->status == STATUS_ALLOC || next_block->status == STATUS_FREE)) {
			next_block = next_block->next;
			ok = 0;
		}
	return ok;
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	if (nmemb == 0 || size == 0)
		return NULL;
	size_t full_size = ALIGN(nmemb * size);
	size_t new_size = ALIGN(full_size + HEADER_SIZE);
	void *ptr;
	// BIG CHUNK - mmap()
	if (full_size + HEADER_SIZE >= PAGE_SIZE) {
		block_header *block;

		block = (block_header *)mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if ((void *)block == (void *)-1)
			return NULL;
		block->size = full_size;
		block->status = STATUS_MAPPED;
		ptr = (char *)block + HEADER_SIZE;
		insert_End_list(block);
		memset(ptr, 0, full_size);
		return ptr;
	}
	//else
	// SMALL CHUNK - brk()

	ptr = os_malloc(full_size);
	memset(ptr, 0, full_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (ptr == NULL)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	block_header *block = get_block_ptr(ptr);

	if (block->status == STATUS_FREE)
		return NULL;

	size_t oldsize = block->size;
	size_t newsize = ALIGN(size);

	if (oldsize < newsize) {
		// check if expand
		if (is_last_block(block)) {
			// expand
			expand_block(block);
			void *newptr = sbrk(newsize - block->size);

			if (newptr == (void *)-1)
				return NULL;
			expand_block(block);
			block->size = newsize;
			block->status = STATUS_ALLOC;
			return ptr;
		}
	}
	expand_block(block);
	oldsize = block->size;
	if (oldsize < newsize) {
		//do NOT expand
		void *new_ptr = os_malloc(size);

		if (!new_ptr)
			return NULL;
		memmove(new_ptr, ptr, oldsize);
		os_free(ptr);
		return new_ptr;
	}
	//else
	// expand_block(block);
	if (block->status == STATUS_ALLOC) {
		split_block(block, newsize);
		return ptr;
	}
	//else
	void *new_ptr = os_malloc(size);

	if (!new_ptr)
		return NULL;
	memmove(new_ptr, ptr, newsize);
	os_free(ptr);
	return new_ptr;
}
