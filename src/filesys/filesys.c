#include "threads/thread.h"
#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

struct dir * parse_path (const char * path_name, char * file_name);

bool filesys_create_dir (const char * name);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();

  //현재 thread의 directory flag를 입력합니다.
  struct thread * t1 = thread_current();
  t1->cur_dir = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  bc_term(); 
 free_map_close ();
  
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  char * file_name = malloc(sizeof(char)*15); 
  struct dir *dir = parse_path(name,file_name); 
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size,0)
                  && dir_add (dir, file_name, inode_sector));
  free(file_name);
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);
  
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */

struct file *
filesys_open (const char *name)
{ 
  char * file_name = malloc(sizeof(char)*15);
  struct dir *dir = parse_path(name,file_name);
  struct inode *inode = NULL;
  
  if (dir != NULL)
    dir_lookup (dir, file_name, &inode);
  dir_close (dir);
  free(file_name);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char * file_name = malloc(sizeof(char)*15);

  //최하단 directory와 file이름으로 parsing합니다.
  struct dir *dir =  parse_path(name,file_name);
  struct inode * inode; 
  bool success;
  
  //directory에서 file을 찾습니다. 
  if(!dir_lookup(dir,file_name,&inode))
  {
   dir_close(dir);
   free(file_name); 
   return false;
  }
  
  //sector 1은 특수한 sector이기 때문에 삭제되면 안됩니다.
  if(inode_get_inumber(inode)==1)
  {
   inode_close(inode);
   dir_close(dir);
   free(file_name); 
   return false;
  }
  
  //directory인 경우와 file인 경우를 나눠서 생각합니다.
  if(inode_is_dir(inode))   
  {
   
   if(inode_get_open_cnt(inode)>1)
   {
     inode_close(inode);
     dir_close(dir);
     free(file_name);
     return false;
   } 
  
   char * in_name = malloc(sizeof(char)*15);
   struct dir * in_dir = dir_open(inode);
   
   //내부에 열린 파일이나 directory가 없는지 확인하고 있으면 false를 return합니다.    
   do
   {
    success = dir_readdir(in_dir,in_name);
   }while(success&&((!strcmp(in_name,".."))||(!strcmp(in_name,"."))));

   if(success)
   {
     dir_close(in_dir);
     dir_close (dir);
     free(in_name);
     free(file_name);
     return false;
   }
  } 
  success = dir != NULL && dir_remove (dir, file_name);
  dir_close (dir); 
  free(file_name);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  struct dir * root = dir_open_root();

  //directory에 ., ..를 추가합니다.
  dir_add(root,".",ROOT_DIR_SECTOR);
  dir_add(root,"..",ROOT_DIR_SECTOR);

  dir_close(root);
  free_map_close ();
  printf ("done.\n");
}

//경로를 분석하여 가장 최하위 directory를 return하고 file_name에 가장 아래 파일을 return합니다. 
struct dir * parse_path (const char * path_name, char * file_name)
{

  struct dir * dir;

  //주어진 인자의 유효성을 검사합니다.
  if (path_name == NULL || file_name == NULL)
     return NULL;

  if (strlen(path_name) == 0)
     return NULL;
    

  char * token, *nextToken, *savePtr;
  char first; 
 
  first = *path_name;


  //이곳에서 상대경로와 절대경로를 구분합니다.  
  if(first == '/')
  dir = dir_open_root();

  else
  dir = dir_reopen(thread_current()->cur_dir);

  char * path_copy=malloc(strlen(path_name)+1);

  strlcpy(path_copy,path_name,strlen(path_name)+1);

  token = strtok_r (path_copy,"/",&savePtr);

  nextToken = strtok_r(NULL,"/",&savePtr);

  struct inode * inode1; 

  while (token != NULL && nextToken !=NULL)
  {
    if(!dir_lookup(dir,token,&inode1))
    return NULL; 
    
    if(!inode_is_dir(inode1))
    return NULL;

    dir_close(dir); 

    dir = dir_open(inode1); 
       
    token = nextToken;

    nextToken = strtok_r(NULL,"/",&savePtr);  
  }
 
 //token이 없으면 자기 자신을 의미합니다. 
 if(token == NULL)
 {
  strlcpy(file_name,".",sizeof(char)*15);
  free(path_copy);
  return dir;
 }
 
 strlcpy(file_name,token,sizeof(char)*15);
 free(path_copy);
 
 return dir; 
}

// directory를 생성하는데 사용하는 함수입니다.
bool filesys_create_dir (const char * name)
{
  
  block_sector_t inode_sector = 0;

  char * file_name = malloc(sizeof(char)*15);
 
  struct dir * dir =  parse_path(name,file_name);

  //dir inode를 생성합니다.
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && dir_create (inode_sector,16)
                  && dir_add (dir, file_name, inode_sector)); 

  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  
  // directory 내부에 "." 와 ".."를 추가합니다.  
  if (success)
  {
    struct dir * made_dir =  dir_open(inode_open(inode_sector));
    dir_add(made_dir,".",inode_sector);
    dir_add(made_dir,"..", inode_get_inumber(dir_get_inode(dir)));
    dir_close(made_dir);
  }

  dir_close (dir);

  free(file_name);

  return success;  
}
 
