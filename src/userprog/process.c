#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/swap.h"
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void argument_stack(char **parse, int count, void **esp);
int process_add_file(struct file *f);
void do_munmap(struct mmap_file * mmap_file);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  

  char *next_ptr;
  char *f1 = (char*)malloc(strlen(file_name)+1);
  strlcpy(f1,file_name,strlen(file_name)+1);
  strtok_r(f1," ",&next_ptr); 
  
 
  /* Create a new thread to execute FILE_NAME. */
  
  tid = thread_create (f1, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
   { palloc_free_page (fn_copy);   
   }
 
 free(f1);
 return tid;
}


/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{ 
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  char *f2=(char*)malloc(strlen(file_name)+1);
  strlcpy(f2,file_name,strlen(file_name)+1);
  char * next_ptr;
  char * token;
  token = strtok_r(f2," ",&next_ptr);
  int count=0;

  while(token!=NULL)
  { 
    token = strtok_r(NULL," ",&next_ptr);
    count++;
  }
  strlcpy(f2,file_name,strlen(file_name)+1);
  char **parse =(char**)malloc(sizeof(char*)*count);
  int i;
  parse[0] = strtok_r(f2," ",&next_ptr);

  for(i=1; i<count; i++)
  { 
    parse[i] = strtok_r(NULL," ",&next_ptr);
  }
  
  
  vm_init(&thread_current()->vm);
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS; 
  success = load(parse[0], &if_.eip, &if_.esp);
  thread_current()->parent->pr_success=success;
  sema_up(&thread_current()->parent->sema_load);
  /* If load failed, quit. */
 
  
  if (!success)
   {    
    free(parse);
    free(f2);
    palloc_free_page (file_name);
    thread_exit();
   }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */ 

  argument_stack(parse,count,&if_.esp);
  palloc_free_page (file_name);
  free(parse);
  free(f2);
   
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
  
}

void argument_stack(char **parse, int count, void **esp)
{
  int i;
  int len;
  int t_len=0;
  for(i=count-1; i>-1; i--)
  { len = strlen(parse[i])+1;
     *esp -= len;
     t_len += len;
    strlcpy(*esp,parse[i],len);
    parse[i] = *esp;
    
  }

   *esp -=(4-(t_len%4))%4; 
  

   *esp -= 4;
   **(uint32_t**)esp = 0;

  for(i=count-1; i>-1; i--)
  {
    *esp -= 4;
    **(uint32_t**)esp = parse[i];
  }

  *esp -= 4;
  **(uint32_t**)esp = *esp + 4;

  *esp -= 4;
  **(uint32_t**)esp = count;

  *esp -= 4;
  **(uint32_t**)esp = 0;

}

int process_add_file (struct file *f)
{ 
  if(f==NULL)
  return -1;
  struct thread * t1=thread_current();
  t1->fdt[t1->next_fd]=f;
  t1->next_fd++;
  return(t1->next_fd-1);
}

struct file * process_get_file(int fd)
{ 
  struct thread * t1=thread_current();
  if(fd<=1||t1->next_fd<=fd)
  return NULL;
  return (t1->fdt[fd]);
}

void process_close_file(int fd)
{
 struct thread * t1 = thread_current();
 if(fd<=1||t1->next_fd<=fd)
 return;
 file_close(t1->fdt[fd]);
 t1->fdt[fd]=NULL;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{ 
 int status1;
 struct thread * t1 = get_child_process(child_tid);
 if(t1==NULL)
{
 return -1;
}
 sema_down(&t1->sema_exit);
 status1 = t1->exit_status;
 
 file_close(t1->run_file);
 remove_child_process(t1);
 
 return status1; 
}

/* Free the current process's resources. */
void
process_exit (void)
{ 
  struct thread *cur = thread_current ();
  uint32_t *pd;
  int cur_fd=cur->next_fd-1;
  int i;
   

   for(i=cur_fd; i>1; i--)
   process_close_file(i); 
  
  while(!list_empty(&cur->mmap_list))
  {  
     struct mmap_file * mf1 = list_entry(list_pop_front(&cur->mmap_list),struct mmap_file,elem);
     do_munmap(mf1);

  }  
 
  vm_destroy (&cur->vm);
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */  
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  /* Open executable file. */
  lock_acquire(&filesys_lock);  
  file = filesys_open (file_name);
  if (file == NULL) 
    { 
      lock_release(&filesys_lock);
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  t->run_file = file;
  file_deny_write(file); 
  lock_release(&filesys_lock);
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  

 done:
  /* We arrive here whether the load is successful or not. */

 return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
/*
      // Get a page of memory. 
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      // Load this page.

      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      // Add the page to the process's address space. 

      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }
*/
      struct vm_entry * ve1 = malloc(sizeof(struct vm_entry));
      ve1->type = VM_BIN;
      ve1->vaddr = (void *)upage;
      ve1->writable = writable;
      ve1->is_loaded = false;
      ve1->file = file;
      ve1->offset = ofs;
      ve1->read_bytes = page_read_bytes; 
      ve1->zero_bytes = page_zero_bytes;
      insert_vme (&thread_current()->vm,ve1);     

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{ 
  bool success = false;
  struct page * kpage = alloc_page(PAL_USER | PAL_ZERO);
   
  if (kpage != NULL) 
    {
   
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage->kaddr, true);
      
      if (success)
        *esp = PHYS_BASE;
      else
        free_page(kpage->kaddr);
    }
 
  struct vm_entry * ve1 = malloc(sizeof(struct vm_entry));

  ve1->type = VM_ANON;
  ve1->vaddr = (uint8_t *) PHYS_BASE - PGSIZE;
  ve1->writable = true;
  ve1->is_loaded = true;
  kpage->vme = ve1;
    
  insert_vme(&thread_current()->vm,ve1);
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

bool handle_mm_fault(struct vm_entry *vme)
{
  
 bool success = false;
 struct page *kpage = alloc_page (PAL_USER); 
 
 if(kpage == NULL)
  { 
    return false;
  }
 
  kpage->vme = vme; 
   
  switch(vme->type)
  {
    case VM_BIN:
    success = load_file(kpage->kaddr,vme);
    break;

    case VM_FILE:   
    success = load_file(kpage->kaddr,vme);
    break;
    
    case VM_ANON:
    swap_in(vme->swap_slot,kpage->kaddr);
    success = true;
    break;


    default: 
    
    return false;  
	       	
  }
    

  if(!success)
  {    
    return false;
  }
 
  if(!install_page(vme->vaddr,kpage->kaddr,vme->writable))
    {       
      return false;
    }
 
   return success;
}



void do_munmap(struct mmap_file * mmap_file)
{
  struct thread * cur = thread_current();
  struct mmap_file * mf1 = mmap_file;
  struct vm_entry * ve1;
  struct list_elem * me1;
  
   while(!list_empty(&mf1->vme_list))
     {
       me1 = list_pop_front(&mf1->vme_list);
     
       ve1 = list_entry(me1,struct vm_entry,mmap_elem);
           
      if(ve1->is_loaded)
      {
        void * kaddr = pagedir_get_page(cur->pagedir,ve1->vaddr);
        if(pagedir_is_dirty(cur->pagedir,ve1->vaddr))
        {  
           lock_acquire(&filesys_lock);
           file_write_at(ve1->file, ve1->vaddr,ve1->read_bytes,ve1->offset);
           lock_release(&filesys_lock);
        }
        free_page(kaddr);        
      }
      delete_vme(&thread_current()->vm,ve1);
     } 
  
 struct file * f1 = mf1->file;
 free(mf1);
 file_close(f1);
}

bool expand_stack(void *addr)
{
  bool success = false;
 
  addr = pg_round_down(addr);

  struct page * kpage = alloc_page(PAL_USER | PAL_ZERO);

  struct vm_entry * ve1 = malloc(sizeof(struct vm_entry));

  ve1->type = VM_ANON;
  ve1->vaddr = addr;
  ve1->writable = true;
  ve1->is_loaded = true;
  kpage->vme = ve1;

  if (kpage != NULL)
    {
      success = install_page (addr, kpage->kaddr, true);

      if (!success)
        free_page(kpage->kaddr);
    }

  insert_vme(&thread_current()->vm,ve1);
  return success;                                 
}

