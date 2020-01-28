#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hash.h>
#include "lib/kernel/hash.h"
#include "userprog/pagedir.h"
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
#include "vm/page.h"



void vm_init (struct hash *vm)
{
   hash_init(vm,vm_hash_func,vm_less_func,NULL);   
}

static unsigned vm_hash_func(const struct hash_elem *e, void * aux)
{
  unsigned result;
  struct vm_entry * e1 = hash_entry(e,struct vm_entry,elem);
  result = hash_int((uintptr_t)e1->vaddr);
  return result;

}

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b)
{
 struct vm_entry * e1 = hash_entry(a,struct vm_entry,elem);
 struct vm_entry * e2 = hash_entry(b,struct vm_entry,elem);
 
 if(e1->vaddr<e2->vaddr)
 return true;

 else return false;

}

bool insert_vme (struct hash *vm, struct vm_entry *vme)
{
  struct hash_elem * e1 = hash_insert(vm,&vme->elem);
  if(e1 == NULL)
  return true;

  else
  return false; 

}

bool delete_vme (struct hash *vm, struct vm_entry *vme)
{
 struct hash_elem * e1 = hash_delete(vm,&vme->elem);
  
 if(e1 == NULL)
 return false;

 else
 {
 free(vme);
 return true;
 }
} 

struct vm_entry * find_vme (void * vaddr)
{
 struct vm_entry ve1;
 struct hash_elem * e1;

 void * pg_num =  pg_round_down (vaddr);  
 ve1.vaddr = pg_num;
 e1 = hash_find(&thread_current()->vm,&ve1.elem);
 return e1!= NULL ? hash_entry(e1,struct vm_entry, elem) : NULL;
 
}

void vm_destroy (struct hash *vm)
{
  hash_destroy(vm, vm_destroy_func);
}

static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
  struct vm_entry * e1 = hash_entry(e,struct vm_entry,elem);
  free(e1);
}

bool load_file (void * kaddr, struct vm_entry *vme)
{
  
  if((size_t)file_read_at (vme->file,kaddr,vme->read_bytes,vme->offset) != vme->read_bytes)
 {
  return false;
 }
 
  memset (kaddr + vme->read_bytes, 0 , vme->zero_bytes);
  return true;
  
}
