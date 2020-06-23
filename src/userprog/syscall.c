#include "userprog/syscall.h"
#include "vm/page.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

struct file
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

struct dir
  { 
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };


struct lock filesys_lock;
struct lock alloc_lock;
struct lock swap_lock;
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)
typedef int mapid_t;
#define MAP_FAILED ((mapid_t) -1);
#define READDIR_MAX_LEN 14
static void syscall_handler (struct intr_frame *f);
struct vm_entry * check_address(void *addr,void *esp /*Unused*/);
void check_valid_buffer (void* buffer, unsigned size, void *esp, bool to_write);
void check_valid_string (const void *str, void * esp);
static mapid_t allocate_mapid (void);

//userprocess project에서 구현한 system call들입니다.
void halt (void); 
void exit (int status);
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

//vm project에서 구현한 system call입니다.
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t mapid);

//filesystem project에서 구현한 system call들입니다.
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char name[READDIR_MAX_LEN + 1]);
bool isdir (int fd);
int inumber (int fd);

void
syscall_init (void) 
{
 
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
  lock_init(&alloc_lock);
  lock_init(&swap_lock);

}

static void
syscall_handler (struct intr_frame *f) 
{
 
  uint32_t * p1 =(uint32_t*) f->esp;
  check_address((void*)p1,(void*)p1);
  
  int syscall_n=*p1;
    
  switch(syscall_n)
  { 
    case SYS_HALT:
    halt();
    break;
    
    case SYS_EXIT:
    check_address((void*)(p1+1),(void*)p1);
    exit(*(p1+1));
    break;
   
    case SYS_EXEC:
    check_address((void*)*(p1+1),(void*)p1);
    check_address((void*)(p1+1),(void*)p1);
    f->eax=exec((const char*)*(p1+1));    
    break;
  
    case SYS_WAIT:
    check_address((void*)(p1+1),(void*)p1);
    f->eax=wait((pid_t)*(p1+1));
    break;

    case SYS_CREATE:
    check_address((void*)(p1+1),(void*)p1);
    check_address((void*)(p1+2),(void*)p1);
    check_address((void*)*(p1+1),(void*)p1);
    f->eax=create((const char*)*(p1+1),(unsigned)*(p1+2));
    break;

    case SYS_REMOVE:
    check_address((void*)(p1+1),(void*)p1);
    check_address((void*)*(p1+1),(void*)p1);
    f->eax=remove((const char*)*(p1+1));
    break;

    case SYS_OPEN:
    check_address((void*)(p1+1),(void*)p1);
    check_address((void*)*(p1+1),(void*)p1);
    f->eax=open((const char*)*(p1+1));
    break;

    case SYS_FILESIZE:
    check_address((void*)(p1+1),(void*)p1);
    f->eax=filesize(*(p1+1));
    break;

    case SYS_READ:
    check_address((void*)(p1+1),(void*)p1);
    check_address((void*)(p1+2),(void*)p1);
    check_valid_buffer((void*)*(p1+2),*(p1+3),(void*)p1,true);
    check_address((void*)(p1+3),(void*)p1);
    f->eax=read(*(p1+1),(void*)*(p1+2),(unsigned)*(p1+3));
    break;

    case SYS_WRITE:
    check_address((void*)(p1+1),(void*)p1);
    check_address((void*)(p1+2),(void*)p1);
    check_valid_string((void*)*(p1+2),(void*)p1);
    check_address((void*)(p1+3),(void*)p1);
    f->eax=write(*(p1+1),(void*)*(p1+2),(unsigned)*(p1+3));
    break;

    case SYS_SEEK:
    check_address((void*)(p1+1),(void*)p1);
    check_address((void*)(p1+2),(void*)p1);
    seek(*(p1+1),(unsigned)*(p1+2));
    break;


    case SYS_TELL:
    check_address((void*)(p1+1),(void*)p1);
    f->eax=tell(*(p1+1));
    break;

    case SYS_CLOSE:
    check_address((void*)(p1+1),(void*)p1);
    close(*(p1+1));
    break;

    case SYS_MMAP:
    f->eax=mmap(*(p1+1),(void*)*(p1+2));
    break;

    case SYS_MUNMAP:
    munmap((mapid_t)*(p1+1));
    break;
    
    case SYS_CHDIR:
    f->eax = chdir ((const char*)*(p1+1)); 
    break;
    
    case SYS_MKDIR:
    f->eax = mkdir ((const char*)*(p1+1));
    break;

    case SYS_READDIR:
    f->eax = readdir(*(p1+1),(char*)*(p1+2));
    break;
  
    case SYS_ISDIR:
    f->eax = isdir(*(p1+1));
    break;

    case SYS_INUMBER:
    f->eax = inumber(*(p1+1));
    break;    

    default :
     exit(-1);
  }
}

struct vm_entry * check_address(void *addr,void *esp /*Unused*/)
{ 
 if(addr<=(void*)0x08048000||addr>=(void *)0xc0000000)  
    exit(-1); 
 struct vm_entry * e1 = find_vme(addr);
 if(e1 == NULL)
  exit(-1);
 return e1;
}

void check_valid_buffer (void* buffer, unsigned size, void * esp, bool to_write)
{ 
  
  if(buffer==NULL)
  exit(-1);

  struct vm_entry * ve1 = check_address(buffer,esp);
  
  if(ve1 == NULL || ve1->writable != true)
  exit(-1);

  void * pg_num1 = pg_round_down(buffer); 
   
  while(pg_num1 >(void *)((uintptr_t)buffer+size))
  {
  ve1 =  check_address(pg_num1,esp); 
  if(ve1 == NULL || ve1->writable != to_write)
  exit(-1);
  pg_num1 =(void *)((uintptr_t)pg_num1 + PGSIZE);
  }
 
}

void check_valid_string (const void *str, void * esp)
{
  struct vm_entry * ve1 =  check_address(str,esp);
  if(ve1==NULL)
 {
  exit(-1);
 }
}

void halt (void)
{
  shutdown_power_off();
}


void exit (int status)
{ 
 struct thread * t1 = thread_current();
 t1->exit_status = status;
 printf("%s: exit(%d)\n",t1->name,status);
 thread_exit();
}

pid_t exec (const char *file)
{
  
 pid_t child_pid;

 child_pid = process_execute(file);
 sema_down(&thread_current()->sema_load);   
 if(thread_current()->pr_success==false)
 return -1;

 
 return child_pid; 
  
}

int 
wait (pid_t pid)
{
  return (process_wait(pid)); 
}


bool
create (const char * file, unsigned initial_size)
{
  
  
  if(file==NULL)
  exit(-1);   
  
  if(strlen(file)>100)
  return false;
  return (filesys_create(file, initial_size));
}

bool
remove (const char *file)
{ 
 
  return (filesys_remove(file));
}


int open(const char * file)
{

 if(file==NULL)
 return -1;

 lock_acquire(&filesys_lock); 
 struct file *f1 = filesys_open(file);
 lock_release(&filesys_lock);
 int fd1 = process_add_file(f1);
  
 
 return (fd1);
}


int filesize(int fd)
{
 struct file * f1 = process_get_file(fd);
 if(f1==NULL)
 return (-1);
 return (file_length(f1));
}

int read(int fd, void * buffer, unsigned size)
{
  
 int i;
 lock_acquire(&filesys_lock); 
 if(fd==0)
 { 

  for(i=0; i<size; i++)
    { 
      ((uint8_t*)buffer)[i] = input_getc();
    }

    lock_release(&filesys_lock);
    return size;
 }
 else 
  { struct file * f1 = process_get_file(fd);
 
    if(f1==NULL)
    {
    lock_release(&filesys_lock);
    return -1;
    }
  
    size=file_read(f1,buffer,size);
  

    lock_release(&filesys_lock);

    return size;   
  }
 
}

int write(int fd, void * buffer, unsigned size)
{  
   lock_acquire(&filesys_lock); 
  if(fd==1)
  {  
   putbuf(buffer,size);
    
    lock_release(&filesys_lock);
      
   return size;
    
  }
  else
  {   
   
    struct file * f1 = process_get_file(fd);
   if(f1==NULL)
    {   
     lock_release(&filesys_lock);
     return -1;
    }
   if(inode_is_dir(f1->inode))
   {
    lock_release(&filesys_lock);
    return -1;
   } 
   size = file_write(f1,buffer,size);
   lock_release(&filesys_lock);
   return size;
   
  }
  
}

void seek(int fd, unsigned position)
{
 struct file * f1 = process_get_file(fd);
 if(f1==NULL)
 exit(-1);
 file_seek(f1,position);
}

unsigned tell(int fd)
{
 struct file * f1 = process_get_file(fd);
 if(f1==NULL)
 exit(-1);
 return (file_tell(f1));
}

void close(int fd)
{
   process_close_file(fd);
}

mapid_t mmap (int fd, void *addr)
{

 if(addr<(void*)0x08048000||addr>=(void *)0xc0000000)
  return MAP_FAILED;
  
 size_t fl1;
 off_t ofs = 0;
 if(fd<2||fd>128||addr==0||addr==NULL)
 {
  return MAP_FAILED;
 }
 if(pg_ofs(addr)!=0)
 { 
  return MAP_FAILED;
 }
 struct file * f1 = process_get_file(fd);
 
 struct list_elem * e1;
  
 fl1 = file_length(f1);
 if(f1 == NULL||fl1==0)
 {
   return MAP_FAILED;
 }
 f1 =  file_reopen (f1);
 if(f1 == NULL)
 {
  return MAP_FAILED;
 }
 mapid_t id1 = allocate_mapid(); 
 struct mmap_file * mf1=malloc(sizeof(struct mmap_file));
 mf1->mapid = id1;
 mf1->file = f1;
 list_push_back(&thread_current()->mmap_list,&mf1->elem);
 list_init(&mf1->vme_list);
 
 int i=0;
 while(fl1>0)
{
 if(find_vme(addr)!=NULL)
 return MAP_FAILED;
 size_t page_read_bytes = fl1< PGSIZE? fl1 : PGSIZE;
 size_t page_zero_bytes = PGSIZE - page_read_bytes;
 struct vm_entry * ve1 = malloc(sizeof(struct vm_entry));
 ve1->type = VM_FILE;
 ve1->vaddr = addr;
 ve1->writable = (!f1->deny_write);
 ve1->is_loaded = false;
 ve1->file = f1;
 ve1->offset = ofs;
 ve1->read_bytes = page_read_bytes;
 ve1->zero_bytes = page_zero_bytes;
 ve1->swap_slot = 9999;
 insert_vme (&thread_current()->vm,ve1);
 list_push_back(&mf1->vme_list,&ve1->mmap_elem);

 fl1 -= page_read_bytes;
 ofs += page_read_bytes;
 addr = (void *)((uintptr_t)addr + PGSIZE);
}

return id1;
}

void munmap (mapid_t mapid)
{ 

  struct thread * cur = thread_current();
  struct list_elem * e1;
  struct mmap_file * mf1;

   for(e1=list_begin(&cur->mmap_list); e1!=list_end(&cur->mmap_list); e1=list_next(e1))
 {
   mf1 = list_entry(e1,struct mmap_file,elem);
   if(mf1->mapid == mapid)
    break;
 }

 
  if((e1) == list_end(&cur->mmap_list))
 { 
   return;
 }
  list_remove(e1); 
  do_munmap(mf1);

 
} 

static mapid_t allocate_mapid (void)
{
 static mapid_t next_mapid = 1;
 mapid_t mapid = next_mapid;

 return mapid;
}

//현재 thread의 cur_dir를 전환합니다.
bool chdir (const char *dir)
{
  char * file_name = malloc(sizeof(char)*15);

  struct dir * real_dir =  parse_path(dir,file_name);

  struct inode * inode = NULL;
 
  dir_lookup(real_dir,file_name,&inode);
  
  dir_close(real_dir);
  
  real_dir = dir_open(inode); 
  
  if(real_dir == NULL)
  {
   free(file_name);
   return false; 
  }
  
  if(thread_current()->cur_dir !=NULL)
  dir_close(thread_current()->cur_dir);
  
  //이곳에서 directory를 전환합니다.
  thread_current()->cur_dir=real_dir;

  free(file_name);

  return true;  
}

//새로운 directory를 생성합니다. 
bool mkdir (const char *dir)
{
  return filesys_create_dir(dir);
}

//directory를 읽어서아무것도 없으면 false를, 파일이 존재하면 true를 return합니다.
bool readdir (int fd, char name[READDIR_MAX_LEN + 1])
{
  bool success = false;

  struct file * f1 = process_get_file(fd);
  
  if(f1 == NULL)
  return false;

  if(!inode_is_dir(f1->inode))
  return false;
  
  inode_reopen(f1->inode); 

  struct dir * p_file = dir_open(f1->inode);

  if(p_file == NULL)
  { 
    inode_close(f1->inode);
    return false; 
  }

  p_file->pos = f1->pos;

  //.과 ..은 모든 directory안에 존재하기 때문에 그것을 제외하고 생각합니다.
  do
  {
    success = dir_readdir(p_file,name); 
  }
  while((success)&&(!strcmp(name,".")||!strcmp(name,"..")));

  f1->pos = p_file->pos;

  dir_close(p_file);
  return success;
}

//주어진 fd 파일의 disk inode가 저장된 sector를 확인하는 system call함수입니다.
int inumber (int fd)
{
 struct file * f1 = process_get_file(fd);
 return inode_get_inumber(f1->inode);

}

//주어진 fd가 directory인지 확인하는 system call함수입니다.
bool isdir (int fd)
{
   struct file * f1 = process_get_file(fd);
   bool result = inode_is_dir(f1->inode);
   return result;  
}

