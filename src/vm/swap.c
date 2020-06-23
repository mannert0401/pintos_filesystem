#include "vm/swap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
struct bitmap * swap_bitmap;
struct block * bl1;
void swap_init(void)
{
  swap_bitmap = bitmap_create(1024);    
}


void swap_in(size_t used_index, void* kaddr)
{
  lock_acquire(&swap_lock);
  
  bl1 = block_get_role(BLOCK_SWAP);
  used_index = used_index * 8;  
  
  int i;
  for(i=0; i<8; i++)
  {  
    
    block_read(bl1,used_index+i,kaddr+(i*BLOCK_SECTOR_SIZE));
    
  } 
  used_index = used_index / 8; 
  bitmap_set(swap_bitmap, used_index, false);

  lock_release(&swap_lock);
  
}

size_t swap_out(void* kaddr)
{

  lock_acquire(&swap_lock);      


  bl1 = block_get_role(BLOCK_SWAP);

 
  size_t swap_num = bitmap_scan(swap_bitmap,0,1,false);
  swap_num = swap_num*8;
 
  size_t i;
  
  for( i=0; i<8; i++)
   {
     block_write(bl1,swap_num + i, kaddr+(i*BLOCK_SECTOR_SIZE) );  
   }
  swap_num = swap_num /8;
  
  bitmap_set(swap_bitmap, swap_num ,true);

  lock_release(&swap_lock); 
  return swap_num;
}

void swap_delete(size_t used_index)
{
  lock_acquire(&swap_lock);
  bitmap_set(swap_bitmap,used_index,true);
  lock_release(&swap_lock);
}
