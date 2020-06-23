#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/buffer_cache.h"
/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DIRECT_BLOCK_ENTRIES 123
#define INDIRECT_BLOCK_ENTRIES 128

/*
  disk 내부의 inode입니다. 2중 inode table로  연결되어 있으며 is_dir flag를 사용하여 file과 directory를 구분합니다.
*/
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t direct_map_table[DIRECT_BLOCK_ENTRIES]; 
    block_sector_t indirect_block_sec; 
    block_sector_t double_indirect_block_sec;
    uint32_t is_dir;
  };

/*
  해당 inode가 data node를 얼마나 가지고 있는지를 나타냅니다.  
  NORMAL_DIRECT : map table에 바로 연결하여 data sector를 저장 중인 상태입니다.
  INDIRECT : indirect_block 한개와 연결하여 data sector를 저장 중인 상태입니다.
  DOUBLE_INDIRECT : indirect block과 2단 연결하여 data sector를 저장 중인 상태입니다.
  OUT_LIMIT : 오류
*/
enum direct_t
  {
    NORMAL_DIRECT,
    INDIRECT,
    DOUBLE_INDIRECT,
    OUT_LIMIT
  };


/*
  data sector가 inode의 어디와 연결되어있는지를 나타내는 구조체입니다.  
*/
struct sector_location
  {
    enum direct_t directness;
    off_t index1;
    off_t index2;
  };

/*
  inode에 연결되는 indirect block입니다. 2중 연결 구조에서는 해당 block아래로 다른 block이 연결됩니다.
*/
struct inode_indirect_block
  {
    block_sector_t map_table[INDIRECT_BLOCK_ENTRIES];
  };


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock extend_lock;    
  };

bool inode_is_dir (const struct inode * inode);

static bool get_disk_inode(const struct inode * inode,struct inode_disk *inode_disk);

static void locate_byte (off_t pos, struct sector_location * sec_loc);

static bool register_sector(struct inode_disk * inode_disk, block_sector_t new_sector, struct sector_location sec_loc);

bool inode_update_file_length(struct inode_disk* inode_disk,off_t start_pos, off_t end_pos);

static block_sector_t byte_to_sector (const struct inode_disk *inode_disk, off_t pos);

/* inode가 directory인지 file을 가리키는지 확인하는 함수입니다. bool함수를 return하여 결과를 확인해줍니다. */
bool inode_is_dir (const struct inode * inode)
 {
   bool result; 

   struct inode_disk * disk_inode = malloc(sizeof(struct inode_disk)); 

   get_disk_inode(inode,disk_inode);

   result = disk_inode->is_dir;
 
   free(disk_inode);

   return result;
 } 


/* memory에 존재하는 inode를 이용하여 disk_inode를 얻는 함수입니다. */
static bool get_disk_inode(const struct inode * inode,struct inode_disk *inode_disk)
  {

     return(bc_read(inode->sector,inode_disk,0,BLOCK_SECTOR_SIZE,0)); 

  }

/* offset을 확인하고 sector_location 구조체에 데이터가 저장될 위치를 입력합니다. */
static void locate_byte (off_t pos, struct sector_location * sec_loc)
{
 /* block 단위로 offset을 나눕니다. */
 off_t pos_sector = pos / BLOCK_SECTOR_SIZE;
 
 /* 
    만약 직접 연결할 수 있는 범위의 offset이라면sector location에 NORMAL_DIRECT를 저장합니다. 
    그리고 index를 설정해줍니다. pos_sector는 몇 번째 direct_block에 저장되는지 알려줍니다. 
 */
 if(pos_sector <(off_t) DIRECT_BLOCK_ENTRIES)
 {
   sec_loc->directness = NORMAL_DIRECT;
   sec_loc->index1 = (pos_sector); 
 }
 
 /*
    direct로 연결할수있는 범위가 넘어가면 indirect block에 연결시켜줍니다. 
    그리고 sector_location에 적절한 정보들을 저장합니다. 
    pos_sector에서 direct block에 저장할 수 있는 양을 빼줍니다. 
    그곳이 indirect block에서 저장되는 순서입니다.
 */
 else if(pos_sector<(off_t)(DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES))
 {
   sec_loc->directness = INDIRECT;
   sec_loc->index1 = (pos_sector-(off_t)DIRECT_BLOCK_ENTRIES);
 }
 
 /*
    indirect_block까지 꽉차면 double_indirect block을 사용해야합니다. 
    그래서 index가 2개 생기는데 index1은 첫 번째 indirect block에서의 index,
    index2는 indirect block안에 저장되어 있는 indirect block에서의 index입니다.
 */
 else if(pos_sector<(off_t)(DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES * (INDIRECT_BLOCK_ENTRIES+1)))
 {
   sec_loc->directness = DOUBLE_INDIRECT;
   sec_loc->index1 = (pos_sector-(off_t)DIRECT_BLOCK_ENTRIES-(off_t)INDIRECT_BLOCK_ENTRIES)/(off_t)INDIRECT_BLOCK_ENTRIES;
   sec_loc->index2 = (pos_sector-(off_t)DIRECT_BLOCK_ENTRIES)%(off_t)INDIRECT_BLOCK_ENTRIES;
 } 
 
 else
   sec_loc->directness = OUT_LIMIT;
}  

/*
   map table의 offset을 구합니다. 
*/
static inline off_t map_table_offset (int index)
{
  return ((off_t)index*4); 
}

/*
   sec_loc 구조체를 참고하여 inode_disk를 수정합니다. 
*/
static bool register_sector(struct inode_disk * inode_disk, block_sector_t new_sector, struct sector_location sec_loc)
{
    
   struct inode_indirect_block * new_block = calloc(1,sizeof(struct inode_indirect_block));
   
   //sector_location의 directness에 따라서 다르게 처리합니다.
   switch(sec_loc.directness)
   {
     // NORMAL_DIRECT의 경우에는 direct_map_table에 index에 직접 새롭게 할당하는 sector를 입력합니다. 
     case NORMAL_DIRECT:
       inode_disk->direct_map_table[sec_loc.index1] = new_sector;
       break;
     
     /*
         INDIRECT의 경우에는 indirect_block이 할당되어있는지 확인합니다. 할당되어 있다면 bc_read를 통하여 읽어온 후
         new_sector를 저장합니다. 할당되어 있지 않다면 먼저 free_map_allocate을 통하여 indirect_block을 할당합니다. 
         그 후 index를 저장합니다. 
     */
     case INDIRECT:
       if(!(inode_disk->indirect_block_sec>0))
       {
         free_map_allocate(1,&inode_disk->indirect_block_sec);
         new_block->map_table[sec_loc.index1] = new_sector;
         bc_write(inode_disk->indirect_block_sec,new_block,0,BLOCK_SECTOR_SIZE,0);
       }

       else
       {
         bc_read(inode_disk->indirect_block_sec, new_block,0,BLOCK_SECTOR_SIZE,0);
         new_block->map_table[sec_loc.index1] = new_sector;
         bc_write(inode_disk->indirect_block_sec,new_block,0,BLOCK_SECTOR_SIZE,0);
       }
   
      break;
     
    /*
        DOUBLE_INDIRECT의 경우에는 double_indirect_block이 할당되어있는지 확인합니다. 
        만약 INDIRECT BLOCK이 할당되어 있지 않다면 새롭게 Indirect block 2개를 할당합니다.
        그리고 new sector를 두 번째 block의 index2에 저장합니다. 
    */
    case DOUBLE_INDIRECT:

    if(!(inode_disk->double_indirect_block_sec>0))
    {
    
       free_map_allocate(1,&inode_disk->double_indirect_block_sec);
       struct inode_indirect_block * ind_block = calloc(1,sizeof(struct inode_indirect_block));
       free_map_allocate(1,&ind_block->map_table[sec_loc.index1]);
       new_block->map_table[sec_loc.index2] = new_sector;
       bc_write(ind_block->map_table[sec_loc.index1],new_block,0,BLOCK_SECTOR_SIZE,0);
       bc_write(inode_disk->double_indirect_block_sec,ind_block,0,BLOCK_SECTOR_SIZE,0); 
    
    }
   
    /*
        만약 해당 block이 할당되어 있다면

        1) index1을 참조하여 이중 연결된 block이 할당되어있는지 확인합니다. 만약 두 번째 block도 할당이 되어있다면
           map_table을 new_sector를 연결합니다. 
 
        2) 두 번째 block이할당되어있지 않다면 indirect_block 할당을 위하여 free_map_allocate을실행하여 두 번째 
           indirect block을 할당하고 new_sector를 저장해줍니다.
    */
    else
    {
       struct inode_indirect_block * ind_block = calloc(1,sizeof(struct inode_indirect_block));
       bc_read(inode_disk->double_indirect_block_sec,ind_block,0,BLOCK_SECTOR_SIZE,0);   
   
       if(ind_block->map_table[sec_loc.index1] > 0)
       {
          bc_read(ind_block->map_table[sec_loc.index1],new_block,0,BLOCK_SECTOR_SIZE,0);
          new_block->map_table[sec_loc.index2] = new_sector;
          bc_write(ind_block->map_table[sec_loc.index1],new_block,0,BLOCK_SECTOR_SIZE,0);
       }
       else
       {

          free_map_allocate(1,&ind_block->map_table[sec_loc.index1]);
          new_block->map_table[sec_loc.index2] = new_sector;
          bc_write(ind_block->map_table[sec_loc.index1],new_block,0,BLOCK_SECTOR_SIZE,0);

       }

       free(ind_block);
    }
    
    break;
 
    default:

    free(new_block);   
    return false;

  }

  free(new_block);
  return true;

}

/*
   write 시 file 크기를 늘릴 수 있게 해주는 함수입니다. 
   extensible file을가능하게 합니다. 
*/
bool inode_update_file_length(struct inode_disk* inode_disk,off_t start_pos, off_t end_pos)
{

    /*
      position을 비교하여 end position이 start position보다 작으면 false를 return합니다.
      같다면 늘릴 필요가 없기 때문에 true를 return합니다.
    */
    if(end_pos==start_pos)
    return true;

    if(end_pos<start_pos)
    return false;

    inode_disk->length = end_pos;

    /*
       offset과 end를 BLOCK_SECTOR_SIZE 단위로 버립니다.
    */
    off_t offset = start_pos/BLOCK_SECTOR_SIZE*BLOCK_SECTOR_SIZE;

    off_t end = (end_pos-1)/BLOCK_SECTOR_SIZE*BLOCK_SECTOR_SIZE;

    void * zeroes = malloc(BLOCK_SECTOR_SIZE);

    zeroes = memset(zeroes,0,BLOCK_SECTOR_SIZE);
     
   
    struct sector_location * sec_loc = malloc(sizeof(struct sector_location));

    /*
       while문을 통하여 file을 확장시킵니다. offset을 BLOCK_SECTOR_SIZE씩 증가시키며
       파일을 확장시킵니다.
    */

    while(offset<=end)
    {
          block_sector_t sector_idx;
          off_t sector_ofs = offset % BLOCK_SECTOR_SIZE;
          
          if(sector_ofs > 0)
          {
             free(zeroes);
             free(sec_loc);
             return false;
          }
 
          else
          {
             //offset을 block sector로 전환합니다.        
             sector_idx = byte_to_sector(inode_disk,offset);
            
             if(sector_idx>0)
             {
               offset += BLOCK_SECTOR_SIZE;
               continue;
             }  
             
             //sec_loc의 변수들을 채워넣습니다.   
             locate_byte(offset,sec_loc);  

             //실질적으로 block을 할당받고 등록합니다.
             if(free_map_allocate(1,&sector_idx))
               register_sector(inode_disk,sector_idx,*sec_loc);
             
             //만약 실패했다면 false를 return합니다. 
             else
             {
               free(sec_loc);
               free(zeroes);
               return false;
             }

             //bc_wrtie를 이용하여 0으로 초기화시킵니다. 
             bc_write(sector_idx,zeroes,0,BLOCK_SECTOR_SIZE,0);

          }

          //offset을 block sector size만큼 증가시킵니다.
          offset += BLOCK_SECTOR_SIZE;
    }
    free(sec_loc);
    free(zeroes);
    return true;
}

 //inode에 연결된 sector들을 free시킵니다.
static void free_inode_sectors(struct inode_disk * inode_disk)
{

   int free_count;
   int double_free_count;
   
   /*
      double_indirect_block_sec가 0보다 크다면 해당 블록이 할당된 것이기 때문에 존재하는 블록을 
      while문을 통하여 free시킵니다. double indirect이기 때문에 free_count와 double_free_count
      두 개의 counter를 사용하여 값을 확인하고 0보다 크다면 무조건 free합니다. 
   */ 
   if(inode_disk->double_indirect_block_sec > 0)
   {
      free_count=0; 
      struct inode_indirect_block * ind_block_1 = malloc(sizeof(struct inode_indirect_block));
      struct inode_indirect_block * ind_block_2 = malloc(sizeof(struct inode_indirect_block));   
      bc_read(inode_disk->double_indirect_block_sec, ind_block_1,0,BLOCK_SECTOR_SIZE,0);
      while(ind_block_1->map_table[free_count] > 0)
      {
         bc_read(ind_block_1->map_table[free_count], ind_block_2,0,BLOCK_SECTOR_SIZE,0);      
         double_free_count=0;   

         while(ind_block_2->map_table[double_free_count] > 0)
         {
             free_map_release(ind_block_2->map_table[double_free_count],1);
             double_free_count++;
         }        
         free_count++;
     }
     free(ind_block_1);
     free(ind_block_2); 
   }  
 
   /*
      indirect_block_sec가 0보다 크다면 해당 블록이 할당된 것이기 때문에 존재하는 블록을
      while문을 통하여 free시킵니다.
   */
   if(inode_disk->indirect_block_sec > 0)
   {
      free_count=0; 
      struct inode_indirect_block * ind_block_1 = (struct inode_indirect_block *) malloc(BLOCK_SECTOR_SIZE);
      bc_read(inode_disk->indirect_block_sec, ind_block_1,0,BLOCK_SECTOR_SIZE,0);   
      
      while(ind_block_1->map_table[free_count] >0)
      {
        free_map_release(ind_block_1->map_table[free_count],1);         
        free_count++;
      }
 
      free(ind_block_1);
   }

   /*
      direct map table에 있는 sector들을 free시킵니다. while문을 통하여 존재하는 모든
      block을 free시킵니다.
   */ 
   free_count=0;

   while(inode_disk->direct_map_table[free_count] > 0)
   {
      free_map_release(inode_disk->direct_map_table[free_count],1);
      free_count++;
   }
}




/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode_disk *inode_disk, off_t pos) 
{
  
  /*  ASSERT (inode != NULL);
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1; */

  block_sector_t result_sec=0;
  
  if(pos<inode_disk->length)
  {
     struct inode_indirect_block *ind_block;
     struct sector_location sec_loc;

     /*
       pos를 이용하여 sec_loc에 정보를 저장합니다. 
     */
     locate_byte(pos,&sec_loc);

     /*
       sec_loc의 directness에 따라서 다른 방식으로 sector를 return합니다.
     */
     switch(sec_loc.directness){
 
          /*
            일반적인 normal_direct상태라면 inode_disk의 map_table의  sec_loc의 index1에서 값을 
            return합니다.
          */
          case NORMAL_DIRECT:

                 result_sec = inode_disk->direct_map_table[sec_loc.index1];
                 break;             

          /*
            Indirect상태라면 indirect_block을 읽어온 후 거기서 index1의 값을 return합니다.
          */
          case INDIRECT:

                 ind_block = malloc(sizeof(struct inode_indirect_block));

                 if(ind_block&&(inode_disk->indirect_block_sec>0))
                 {
                      bc_read(inode_disk->indirect_block_sec, ind_block,0,BLOCK_SECTOR_SIZE,0);
                      result_sec = ind_block->map_table[sec_loc.index1]; 
                 }
  
                 else 
                      result_sec = 0; 
                  
                 free (ind_block);

                 break; 

            /*
               Double_direct상태라면 read를 두 번해서 double_indirect_block을 불러온 후 거기에서
               값을 return합니다.
            */
            case DOUBLE_INDIRECT:
          
                ind_block = malloc(sizeof(struct inode_indirect_block));

                if(ind_block&&(inode_disk->double_indirect_block_sec>0))
                {
                      bc_read(inode_disk->double_indirect_block_sec, ind_block,0,BLOCK_SECTOR_SIZE,0);
                      bc_read(ind_block->map_table[sec_loc.index1],ind_block,0,BLOCK_SECTOR_SIZE,0);
                      result_sec = ind_block->map_table[sec_loc.index2];
                }

                else
                      result_sec = 0;
            
                free(ind_block);

                break;
               
            default : 

                result_sec = 0;

                break;                      
        }
    }
    return result_sec;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */

bool
inode_create (block_sector_t sector, off_t length,uint32_t is_dir)
{
  
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      //disk_inode에 데이터들을 저장합니다.
      disk_inode->length =length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = is_dir; 
/*      if (free_map_allocate (sectors, &disk_inode->start)) 
        {
          block_write (fs_device, sector, disk_inode);
          if (sectors > 0) 
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) 
                block_write (fs_device, disk_inode->start + i, zeros);
*/    

     /*
        length가 0보다 크거나 같으면 inode_update_file_length를 실행하여 
        block을 할당받습니다.
     */
      if(length >= 0)
     {
       success = inode_update_file_length(disk_inode,0,length);
     }
      
   }

  //생성한 inode를 저장합니다. 
  bc_write(sector , disk_inode, 0, BLOCK_SECTOR_SIZE,0);

  free(disk_inode);

  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->extend_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

int
inode_get_open_cnt (const struct inode *inode)
{
  return inode->open_cnt;
}
/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{

  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Dallocate blocks if removed. */
      if (inode->removed) 
        {
          struct inode_disk * disk_inode = malloc(sizeof(struct inode_disk));
          get_disk_inode(inode,disk_inode);
          free_inode_sectors(disk_inode);
          free_map_release (inode->sector, 1);
          free(disk_inode);         
        }

        free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
/*  uint8_t *bounce = NULL;*/
  struct inode_disk * disk_inode = malloc(sizeof(struct inode_disk));
  if(disk_inode == NULL)
    return 0;
  
  //inode를 이용하여 disk_inode를 얻습니다.   
  get_disk_inode(inode,disk_inode);
   
  //block단위로 읽어옵니다.
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      
      block_sector_t sector_idx = byte_to_sector (disk_inode, offset);
      
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = disk_inode->length - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
     { 
       break;
     }
      //기존에 사용하던 bounce buffer 대신 bread를 이용하여 buffer에 바로 읽습니다.
      bc_read(sector_idx,(void*)buffer,bytes_read,chunk_size,sector_ofs);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

/*  free (bounce);*/
  free(disk_inode); 
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  /* uint8_t *bounce = NULL;*/

  //읽기 전용 파일이라면 0을return합니다.
  if (inode->deny_write_cnt)
    return 0;

  struct inode_disk * disk_inode = malloc(sizeof(struct inode_disk));
  if(disk_inode == NULL)
    return 0;

  //파일을 확장할 때는 extend_lock을 획득합니다.
  lock_acquire(&inode->extend_lock);
  get_disk_inode(inode,disk_inode);
  
  int old_length = disk_inode->length;
  int write_end = offset + size-1;
  
  //이곳에서 파일을 실제로 늘립니다. 만약 쓰기의 끝이 현재보다 작다면 실행하지 않습니다. 
  if(write_end > old_length -1)
  { 
    inode_update_file_length(disk_inode,old_length,write_end+1);
    //확장된 disk inode를 update합니다.
    bc_write(inode->sector,disk_inode,0,BLOCK_SECTOR_SIZE,0);
  }
  
  //파일확장이 끝났으니 extend_lock을 해방합니다.
  lock_release(&inode->extend_lock);


  //read때와 같이 bounce buffer대신 bc_write를 이용하여 쓰기 작업을 완료합니다.
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (disk_inode, offset);
       
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        {   
          break;
        }
        bc_write(sector_idx,(void*)buffer,bytes_written,chunk_size,sector_ofs);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    
     }

/*  free (bounce);*/
  free(disk_inode);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk * disk_inode  = malloc(sizeof(struct inode_disk));
  get_disk_inode(inode,disk_inode); 
  off_t length = disk_inode->length;
  free(disk_inode);
  return length;
 }
