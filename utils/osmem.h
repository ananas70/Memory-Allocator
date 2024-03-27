/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "printf.h"
#include <block_meta.h>

typedef struct block_meta block_header;


void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);
void split_block(block_header *block, size_t needed);
void *find_best_fit(size_t size);
block_header *request_space(size_t size);
block_header *get_block_ptr(void *ptr);
void insert_End_list(block_header *newblock);
void coalesce_immediate(block_header *block);
void remove_block_from_list(block_header* block);
void expand_block(block_header *start_block);
int is_last_block(block_header *block);

