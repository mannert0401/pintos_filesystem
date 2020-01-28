#include "threads/thread.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

struct list lru_list;
struct lock lru_list_lock;
struct list_elem * lru_clock;

static struct list_elem* get_next_lru_clock();

void lru_list_init (void)
{
 list_init(&lru_list);
 lock_init(&lru_list_lock);
 lru_clock = NULL;

}

void add_page_to_lru_list(struct page* page)
{ 
 
  list_push_front(&lru_list,&page->lru);
 
}

void del_page_from_lru_list(struct page* page)
{
 
 if(&page->lru == lru_clock)
 lru_clock = list_remove(&page->lru);
 else
 list_remove(&page->lru);
}

struct page* alloc_page(enum palloc_flags flags)
{
 lock_acquire(&lru_list_lock); 
 void * pg1 =  palloc_get_page(flags); 
 if(pg1 == NULL)
 {
  pg1 = try_to_free_pages(flags);  
 }
 lock_release(&lru_list_lock);
 struct page * p1 = malloc(sizeof(struct page));
 ASSERT(p1 != NULL);
 p1->kaddr = pg1;
 p1->thread = thread_current();

 add_page_to_lru_list(p1);

 return (p1);
}

void free_page(void *kaddr)
{ 
  
  struct list_elem * e1;
  struct page * p1;
  bool flag=0;

  lock_acquire(&lru_list_lock);
  for(e1=list_begin(&lru_list); e1!=list_end(&lru_list); e1=list_next(e1))
 {
   p1 = list_entry(e1,struct page, lru);
   if(p1->kaddr == kaddr)
   {
    flag = 1;
    break;
   }
 }
 ASSERT(flag==1);

 __free_page(p1); 
 lock_release(&lru_list_lock);
}

void __free_page(struct page* page)
{ 
 
 del_page_from_lru_list(page);
 pagedir_clear_page(page->thread->pagedir,page->vme->vaddr);
 palloc_free_page(page->kaddr);
 free(page);
 
}

static struct list_elem* get_next_lru_clock()
{

 if(lru_clock == NULL||(list_next(lru_clock)==list_end(&lru_list)))
 {
    if(list_empty(&lru_list))
    {  
     return NULL;
     }
    else      
    return list_begin(&lru_list);
 } 
 return list_next(lru_clock);
}

void* try_to_free_pages(enum palloc_flags flags)
{  
    
   if(lru_clock==NULL) 
    lru_clock = get_next_lru_clock(); 
   
   struct page * p1 = list_entry(lru_clock,struct page,lru); 
   
    while(pagedir_is_accessed(p1->thread->pagedir,p1->vme->vaddr))
   {  
     pagedir_set_accessed(p1->thread->pagedir,p1->vme->vaddr,false); 
     lru_clock = get_next_lru_clock();
     ASSERT(lru_clock!=NULL);
     p1 = list_entry(lru_clock,struct page,lru);
     
   } 
       
   switch(p1->vme->type)
  {  
    case VM_BIN :
    if(pagedir_is_dirty(p1->thread->pagedir,p1->vme->vaddr))
    {
     p1->vme->swap_slot = swap_out(p1->kaddr); 
     p1->vme->type = VM_ANON; 
    }
    break;

    case VM_FILE :
    if(pagedir_is_dirty(p1->thread->pagedir,p1->vme->vaddr))
    {
    lock_acquire(&filesys_lock);
    file_write_at(p1->vme->file,p1->vme->vaddr,PGSIZE,p1->vme->offset);
    lock_release(&filesys_lock);
    }
    break;

    case VM_ANON :
    p1->vme->swap_slot = swap_out(p1->kaddr);
    break;

    default :
     printf("\nwrong type!\n");
     return NULL;
  } 
  
  p1->vme->is_loaded == false;
   
  __free_page(p1);   

  void * kaddr2 = palloc_get_page(flags);
  if(kaddr2==NULL)
  printf("\nmonnje itda.....\n");

  printf("\n new kaddr!@!!!! : %p\n",kaddr2);
  return kaddr2;
}


