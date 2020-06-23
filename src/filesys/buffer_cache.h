#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "filesys/inode.h"
#include "threads/synch.h"

struct buffer_head{

     /*
       Buffer cache 안에 있는 데이터가 dirty한 상태인지 표시하는 flag입니다. 이 flag를 이용하여 write back 여부를 결정합니다.
     */
     bool dirty; 

     /*
       해당 buffer 공간이 load가 되어있는지 확인하는 flag입니다. 아직 data가 load되지 않았다면 0으로 설정되고 data가 load된다면 1로 설정됩니다.
     */
     bool cache_loaded;

     /*
       Buffer cache에 저장되어 있는 data가 실제로 disk의 어떤 sector인지 알려주는 flag입니다.
     */
     block_sector_t sector;
   
     /*
       Buffer cache의 victim에 사용하는 flag입니다. Accessed_bit와 비슷한 역할을 합니다.
     */
     bool clock_bit;

     /*
       실제 sector를 저장하는 pointer입니다. 만약 앞으로 해당 sector가 불려지면 memcpy를 통해 data를 사용합니다.
     */
     void* data;
     struct lock buffer_lock;
};

void bc_init(void);

void bc_term(void);

struct buffer_head * bc_select_victim (void);

struct buffer_head * bc_lookup (block_sector_t sector);

void bc_flush_entry(struct buffer_head *p_flush_entry);

void bc_flush_all_entries (void);

bool bc_read (block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs);

bool bc_write (block_sector_t sector_idx, void * buffer, off_t bytes_written, int chunk_size, int sector_ofs);

#endif /* filesys/buffer_cache.h */
