#include "filesys/buffer_cache.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"


/* buffer cache의 크기는 64개입니다. */
#define BUFFER_CACHE_ENTRY_NB 64

/* buffer head의 descriptor table입니다. 총 64개를 보관합니다. */
struct buffer_head * buffer_hdt[64];

/* lru algorithm의 clock입니다. */
int clock_hand;

/* buffer가 사용되고있는 개수입니다. */
int buffer_count;

/* buffer cache를 초기화합니다. 모든 buffer head를 할당받고 flag들을 0으로 초기합니다.
   sector 에서의 0값은 실제 sector 0과 헷갈릴 수 있기 때문에 9999를 할당합니다.
   또한 buffer head의 data에 block 한개 크기의 메모리를 할당하여caching 공간을 준비합니다.
   효율적인 synchronization을 위하여 모든 buffer cache마다 lock을 사용하여 사용을 제한합니다.*/
void bc_init(void) 
{
 
  int i =0;
  
  /* for문을 통하여 bht의 모든 buffer head를 활성화시킵니다. */
  for(i=0; i<BUFFER_CACHE_ENTRY_NB; i++)
  {
     struct buffer_head * bh1;
     bh1=malloc(sizeof(struct buffer_head)); 
     bh1->dirty = 0;
     bh1->cache_loaded = 0;
     bh1->clock_bit = 0;
     bh1->sector = 9999;

     bh1->data = malloc(BLOCK_SECTOR_SIZE);

     lock_init(&bh1->buffer_lock);
     
     /* buffer head descriptor table에해당 buffer head를 삽입합니다. */ 
     buffer_hdt[i]=bh1;
  }

  /* 효율적인 victim을 위해 사용되는 flag를 초기화합니다. */
  buffer_count = 0;
  clock_hand = 0;

}


/* buffer cache를 없앨 때 사용하는 함수입니다. file system 종료 시 사용됩니다. */
void bc_term(void)
{
 
 /* 
  buffer cache에 저장되어 있는 모든 buffer head를 방출하고 dirty page라면 write back합니다.
 */
 bc_flush_all_entries();

  
 int i =0;
 
 /* for문을 통하여 init시에 할당했던 모든 memory를 free합니다. */
 for(i=0; i<BUFFER_CACHE_ENTRY_NB; i++)
 {
   free(buffer_hdt[i]->data);
   free(buffer_hdt[i]);
 }

}

/*
   buffer cache가 꽉차서 eviction이발생할 때 victim을 선정할 때 사용하는 함수입니다. 
*/
struct buffer_head * bc_select_victim (void)
{

  /*
   while문을 통하여 clock hand를 증가시키면서 buffer_hdt를 traverse합니다. 만약 해당 head에
   clock_bit가 true인 경우라면 break하고 아니라면 clock_bit를 true로 변경시키고 다음 buffer
   head로 넘어갑니다. 만약 63까지 찾았는데 없다면 다시 0으로 돌아가서 진행합니다.
  */
  struct buffer_head * victim_head;
 
  while(1)
  {
     if(buffer_hdt[clock_hand]->clock_bit == true)
     break;
     else
     buffer_hdt[clock_hand]->clock_bit=true;
 
     if(clock_hand==63)
     clock_hand = 0;
     else
     clock_hand++;
  }
  
  victim_head = buffer_hdt[clock_hand];
  ASSERT(victim_head->cache_loaded == true);
  
  /* 만약 해당 buffer head가 dirty한 상태라면 write back을 하고 flag를 false로 바꿉니다. */
  if(victim_head->dirty)
  {
    block_write(fs_device,victim_head->sector,victim_head->data);
    buffer_hdt[clock_hand]->dirty = false;
  }
  
  /*
    clock_hand를 다음 순번으로 바꾼 후 victim head를 return합니다.
  */
  if(clock_hand==63)
    clock_hand = 0;

  else 
    clock_hand++; 
 
  return  victim_head;
 
}

/* buffer cache에서 인자로 받은 sector를 저장하고 있는 buffer head를 return합니다.*/
struct buffer_head * bc_lookup (block_sector_t sector)
{
 int i = 0;
 
 struct buffer_head* bh1=NULL;
 
 /* for문을 통하여 buffer hdt가 유효하고 해당 sector를 포함하고 있는지 확인합니다. */
 for(i=0; i<buffer_count; i++)
 {
   if((buffer_hdt[i]->sector == sector)&&(buffer_hdt[i]->cache_loaded==true))
   {
     bh1 = buffer_hdt[i];
     break;
   }
 }
 
 /* sector에 대응되는 bh가 없다면 NULL을 return합니다. */ 
 if(bh1 == NULL)
  return NULL;
 
 /* 찾은 bh를 return합니다. */
 else
  return bh1;
 
}

/* 해당 buffer head를 write back 시켜줍니다. */
void bc_flush_entry(struct buffer_head *p_flush_entry)
{

  ASSERT(p_flush_entry!=NULL);
  ASSERT(p_flush_entry->cache_loaded == 1);

  /* write를 하고 dirty flag를0으로 초기화합니다. */
  block_write(fs_device,p_flush_entry->sector,p_flush_entry->data);
  p_flush_entry->dirty = 0;

}

/* buffer cache의 모든 bh를 flush합니다. bc_flush_entry를 사용합니다. */
void bc_flush_all_entries (void)
{

  int i = 0; 
  
  /*for문을 돌면서 dirty상태의 모든buffer head를 write back시켜줍니다. */
  for (i=0; i<64; i++)
  {
     if(buffer_hdt[i]->dirty&&buffer_hdt[i]->cache_loaded)
     {
       block_write(fs_device,buffer_hdt[i]->sector,buffer_hdt[i]->data) ;
       buffer_hdt[i]->dirty = 0; 
     }
  }

}

/* 
READ시 작업시 사용되는 함수입니다. buffer cache를 먼저 접근하여 read 작업을 빠르게 만듭니다. */
bool bc_read (block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs)
{

 bool success = false;

 /* 인자로 받은 sector를 이용하여 대응되는 buffer head를 찾습니다. */
 struct buffer_head * bh1 = bc_lookup(sector_idx);

 /* 
    bh1이NULL이라면 해당 sector는 caching이 되어있지 않은 것입니다. 따라서 block device에서
    sector를 읽은 후 빈 buffer head에 저장합니다. 만약 buffer head가 비어있지 않다면 
    victim을 선정하여 방출하고 새로 저장합니다. 
 */
 if(bh1==NULL)
 {
  
   /* buffer가 꽉차있다면 bc_select_victim을 통하여 victim을 선정하고 sector flag를 인자로 받은 sector_idx로 설정합니다. */ 
   if(buffer_count==64)
   {
      bh1 = bc_select_victim();
      lock_acquire(&bh1->buffer_lock);
      bh1->cache_loaded = 1;
      bh1->sector = sector_idx;
   }

   /* 만약 buffer가 꽉차있지 않다면 buffer count 위치에 있는 buffer head를 사용합니다. 그리고 buffer count를 1 증가시킵니다. */
   else
   { 
      bh1 = buffer_hdt[buffer_count];
      lock_acquire(&bh1->buffer_lock);
      bh1->cache_loaded = 1;
      bh1->sector = sector_idx;
      buffer_count++;
   }
   
   /* 그리고 buffer head의 data로 sector를 읽어옵니다. */
   block_read (fs_device, bh1->sector, bh1->data);
 }
 
 else
   lock_acquire(&bh1->buffer_lock);

 ASSERT(bh1!=NULL);

 /* 이후부터는 해당 sector의 data가 무조건 buffer cache안에 존재햐아합니다. buffer cache안의 데이터를 memory로 copy합니다. */
 memcpy((void*)((uintptr_t)buffer + bytes_read),(void*)((uintptr_t)bh1->data + sector_ofs),chunk_size);
 success = true;
 bh1->clock_bit = 0;
 lock_release(&bh1->buffer_lock);

 return success; 

} 

/* write를 진행할 때 사용하는 함수입니다. */
bool bc_write (block_sector_t sector_idx, void * buffer, off_t bytes_written, int chunk_size, int sector_ofs)
{
 
 bool success = false; 

 /* read때 했던 것처럼 sector_idx와 대응된는 buffer head를 찾습니다. */
 struct buffer_head * bh1 = bc_lookup(sector_idx);

 if(bh1 ==NULL)
 { 
   /* buffer count가 64, 즉 buffer가 꽉차있을 때는 victim을 선택하여 victim에 데이터를 저장합니다. */       
   if(buffer_count==64)
   {
    bh1 = bc_select_victim();
    lock_acquire(&bh1->buffer_lock);
    bh1->cache_loaded = 1;
    bh1->sector = sector_idx;
   }
   
   /* 
      buffer count가 64미만, buffer에 아직 빈 head가 남아있을 경우에는 buffer count를 참조하여 buffer를 할당하고
      buffer count를 증가시킵니다.
   */
   else
   {
     bh1 = buffer_hdt[buffer_count];
     lock_acquire(&bh1->buffer_lock);
     bh1->cache_loaded = 1;
     bh1->sector = sector_idx;
     buffer_count++;
   }
   
   /*
     buffer head로 실제 data를 읽어옵니다.
   */
   block_read (fs_device, bh1->sector, bh1->data);
 }

 else
 lock_acquire(&bh1->buffer_lock);
 
 ASSERT(bh1!=NULL);

 /* memcpy 함수를 이용하여 memory에서 buffer cache로 데이터를 복사합니다. 쓰기 작업이기 때문에 dirty bit가 켜집니다. */
 memcpy((void*)((uintptr_t)bh1->data+sector_ofs),(void*)((uintptr_t)buffer+bytes_written),chunk_size);

 success = true;
 bh1->clock_bit = 0;
 bh1->dirty = 1;
 lock_release(&bh1->buffer_lock);
 return success;
}


