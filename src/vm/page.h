#include <debug.h>
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


#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

struct vm_entry
{
uint8_t type;
void *vaddr;
bool writable;

bool is_loaded;
struct file * file;

struct list_elem mmap_elem;

size_t offset;
size_t read_bytes;
size_t zero_bytes;

size_t swap_slot;

struct hash_elem elem;
}; 
 
struct mmap_file {
	int mapid;
	struct file* file;
	struct list_elem elem;
	struct list vme_list;
};

struct page {
	void *kaddr;
	struct vm_entry *vme;
	struct thread * thread;
	struct list_elem lru;
};

void vm_init (struct hash *vm);

static unsigned vm_hash_func(const struct hash_elem *e, void * aux);

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b);

bool insert_vme(struct hash *vm, struct vm_entry *vme);

bool delete_vme (struct hash *vm, struct vm_entry *vme);

struct vm_entry * find_vme (void * vaddr);

void vm_destroy (struct hash *vm);

static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED);

bool load_file (void * kaddr, struct vm_entry *vme);









