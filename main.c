#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/user.h>

#include "elfhash.h"

/*wraper functions for 32bit/64bit*/
static int is_valid_elf(char *base)
{
 if(is_32bit_elf(base))
    return is_valid_elf32(base);
 if(is_64bit_elf(base))
    return is_valid_elf64(base);
}

static int has_gnuhash(char *base)
{
 if(is_32bit_elf(base))
   return has_gnuhash32(base);
 if(is_64bit_elf(base))
   return has_gnuhash64(base);
}

static int rename_func(char *base, const char *old_func, const char *new_func)
{
 if(is_32bit_elf(base))
   return rename_func32(base, old_func, new_func);
 if(is_64bit_elf(base))
   return rename_func64(base, old_func, new_func);
}

static int rehash(char *base)
{
 if(is_32bit_elf(base))
    return rehash32(base);
 if(is_64bit_elf(base))
    return rehash64(base);
}
static int convert_gnu_to_sysv(char *base, unsigned long size, unsigned long gap)
{
 if(is_32bit_elf(base))
    return convert_gnu_to_sysv32(base, size, gap);
 if(is_64bit_elf(base))
    return convert_gnu_to_sysv64(base, size, gap);
}
static void elfhash_listcontent(char* base)
{
 if(is_32bit_elf(base))
    return elfhash_listcontent32(base);
 if(is_64bit_elf(base))
    return elfhash_listcontent64(base);
}
unsigned long elfhash_compute_gap(void*base)
{
 if(is_32bit_elf(base))
    return elfhash_compute_gap32(base);
 if(is_64bit_elf(base))
    return elfhash_compute_gap64(base);
}



static void elfhash_usage(const char*name)
{
  printf("Manipulate and convert elf hash section and replace elf dynamic symbols\n");
  printf("\t\t\t---By Cjacker <cjacker@gmail.com>\n\n");
  printf("Usage: %s <options> file\n\n", name);
  printf("Options:\n");
  printf("  --  if without any options, always convert .gnu.hash to .hash if it exists\n\n");
  printf("  -l  list elf contents\n\n");
  printf("  -r  rehash elf sysv style hash after change elf symbol manually\n");
  printf("      NOT work with gnu style hash, you need convert it first\n\n");
  printf("  -f oldname -t newname \n");
  printf("      replace the dynamic symbol from oldname to newname and rehash the elf\n");
  printf("      if elf file contains a gnu style hash, it will be convert to sysv hash\n\n");
  printf("  -h  display this message\n");
  exit(0);
}


struct globalArgs_t {
  int list;  //-l  list elf contents
  int help;  //-h  help
  int reh;   //-r  rehash
  char *old_func; //-f old function be renamed.
  char *new_func; //-t new function rename to.
  char **inputFiles; // input file;
  int numInputFiles; // count of input file, should always be 1. this is we limited.
} globalArgs;


static const char *optString = "lhrcf:t:";

int main(int argc, char**argv)
{
  if(argc == 1) {
    elfhash_usage(argv[0]);
  }

  int opt = 0;
  globalArgs.list = 0;
  globalArgs.help = 0;
  globalArgs.reh = 0;
  globalArgs.old_func = NULL;
  globalArgs.new_func = NULL;
  globalArgs.inputFiles = NULL;
  globalArgs.numInputFiles = 0;

  opt = getopt( argc, argv, optString );
  while( opt != -1 ) {
    switch( opt ) {
    case 'l': 
      globalArgs.list = 1;
      break;
    case 'r':
      globalArgs.reh = 1;
      break;
    case 'f':
      globalArgs.old_func = optarg;
      break;
    case 't':
      globalArgs.new_func = optarg;
      break;
    case 'h':
      elfhash_usage(argv[0]);
      break;
    default:
      //never here.
      break;
    }
    opt = getopt( argc, argv, optString );
  }
  globalArgs.inputFiles = argv + optind;
  globalArgs.numInputFiles = argc - optind;

  if(globalArgs.numInputFiles != 1) { 
    fprintf(stderr,"Please supply one elf file each time\n");
    exit(0);
  }

  // -f and -t must be used at same time.
  if((!globalArgs.old_func)^(!globalArgs.new_func)) {
    fprintf(stderr,"Please use -f and -t at the same time\n");
    exit(0);
  }

  if(globalArgs.old_func && globalArgs.new_func 
     && (strlen(globalArgs.old_func) != strlen(globalArgs.new_func))) {
    fprintf(stderr, "The old and new function name must be same length!\n");
    exit(0);
  }


  /* ** file init */
  const char *filename = globalArgs.inputFiles[0];

  int fd = open(filename, O_RDWR);
  if(fd == -1) {
    fprintf(stderr, "file '%s' cannot be opened (%s).\n", filename, strerror(errno));
    return 0;
  }
  int rc;
  struct stat s;
  rc = fstat(fd, &s);
  unsigned long size = s.st_size;
  //NOTE, here we map it as readonly.
  char *base = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0); 
  if(!base) {
    fprintf(stderr, "file '%s' is not readable (%s).\n", filename, strerror(errno));
    return 0;
  }


  if(!is_valid_elf(base)) {
    close(fd);
    exit(1);
  }
  
  if(is_32bit_elf(base))
    printf("%s is a 32bit elf\n", filename);
  else if(is_64bit_elf(base))
    printf("%s is a 64bit elf\n", filename);
  else
    exit(1);
 
  //if there is .gnu.hash exist, convert it except you use -l option
  if(has_gnuhash(base) && !globalArgs.list) {
    /* Calculate gap */
    unsigned long gap = elfhash_compute_gap(base);

    /* Grow the file */
    munmap(base, size);
    size += gap;
    rc = ftruncate(fd, size);
    if(rc) {
      return 1;
    }
    base = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if(!base) {
      return 1;
    }
    convert_gnu_to_sysv(base, size, gap);
  }

  //process options.
  if(globalArgs.list) {
     /* show elf contents */
    elfhash_listcontent(base);
  } else if(globalArgs.reh) {
    /* rehash */
    //remap it to write.
    munmap(base, size);
    base = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    //rehash
    rehash(base);
  } else if(globalArgs.old_func || globalArgs.new_func) {
      munmap(base, size);
      base = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
      int ret = rename_func(base, globalArgs.old_func , globalArgs.new_func);
      //after rename, rehash
      if(ret)
        rehash(base);
  }
 
  close(fd);
  return 0;
}
