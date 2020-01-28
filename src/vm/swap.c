#include "vm/swap.h"
#include "vm/page.h"
#include "devices/block.h"

struct bitmap * swap_bitmap;
struct lock swap_lock;

void swap_init(void)
{
  swap_bitmap = bitmap_create(1024);    
  lock_init(&swap_lock);
}


void swap_in(size_t used_index, void* kaddr)
{

  printf("\n swap_in call!!!!\n"); 
  struct block * bl1 = block_get_role(BLOCK_SWAP);
  ASSERT(bl1!=NULL)   
  
  bitmap_set(swap_bitmap, used_index, false);
  
  used_index = used_index * 8;  
  
  int i;
   for(i=0; i<8; i++)
  {  
    block_read(bl1,used_index+i,kaddr+i*BLOCK_SECTOR_SIZE);
  }

  
}

size_t swap_out(void* kaddr)
{
      
  struct block * bl1 = block_get_role(BLOCK_SWAP);
  ASSERT(bl1 != NULL);
   
  size_t swap_num = bitmap_scan(swap_bitmap,0,1,false);
     
  bitmap_set(swap_bitmap, swap_num ,true);
   
  printf("\n new swap : %d\n",swap_num);
  swap_num = swap_num*8;

  int i;
 
  for( i=0; i<8; i++)
   {
    block_write(bl1,swap_num + i,kaddr+i*BLOCK_SECTOR_SIZE);  
   }
  swap_num = swap_num /8;
  
return swap_num;
}

