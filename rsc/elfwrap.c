/** @file elfwrap- wraps symbols in an already linked ELF library.
 * @author Alexandre DENIS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <elf.h>

#ifndef PAGE_SIZE
#  define PAGE_SIZE (getpagesize())
#endif

#define _ID(N) N
#define _PASTE(A, B) A ## B

#define SIZEOF_LONG 8 

#if ( SIZEOF_LONG == 4)
#  define ElfXX Elf32
#  define ElfXX_Ehdr  Elf32_Ehdr
#  define ElfXX_Shdr  Elf32_Shdr
#  define ElfXX_Phdr  Elf32_Phdr
#  define ElfXX_Addr  Elf32_Addr
#  define ElfXX_Word  Elf32_Word
#  define ElfXX_Sword Elf32_Sword
#  define ElfXX_Sym   Elf32_Sym
#  define ElfXX_Dyn   Elf32_Dyn
#  define ElfXX_Half  Elf32_Half
#  define ELFXX_ST_TYPE(I) ELF32_ST_TYPE(I)
#elif ( SIZEOF_LONG == 8)
#  define ElfXX Elf64
#  define ElfXX_Ehdr  Elf64_Ehdr
#  define ElfXX_Shdr  Elf64_Shdr
#  define ElfXX_Phdr  Elf64_Phdr
#  define ElfXX_Addr  Elf64_Addr
#  define ElfXX_Word  Elf64_Word
#  define ElfXX_Sword Elf64_Sword
#  define ElfXX_Sym   Elf64_Sym
#  define ElfXX_Dyn   Elf64_Dyn
#  define ElfXX_Half  Elf64_Half
#  define ELFXX_ST_TYPE(I) ELF64_ST_TYPE(I)
#else
#  error "SIZEOF_LONG undefined."
#endif



struct elfwrap_alias_s
{
  const char*sym;
  const char*alias;
};

struct elfwrap_alias_s elfwrap_alias_table[] =
  {
//#include "elfwrap-table.h"
    { .sym = NULL, .alias = NULL}
  };

/** section header types names. Only used for debug output */
const char*sh_types[] =
  {
    [0]  = "NULL",
    [1]  = "PROGBITS",
    [2]  = "SYMTAB",
    [3]  = "STRTAB",
    [4]  = "RELA",
    [5]  = "HASH",
    [6]  = "DYNAMIC",
    [7]  = "NOTE",
    [8]  = "NOBITS",
    [9]  = "REL",
    [10] = "SHLIB",
    [11] = "DYNSYM"
  };

/** program header types names. Only used for debug output */
const char*ph_types[] =
  {
    [0] = "NULL",
    [1] = "LOAD",
    [2] = "DYNAMIC",
    [3] = "INTERP",
    [4] = "NOTE",
    [5] = "SHLIB",
    [6] = "PHDR"
  };

/** Get a section header from its index */
static ElfXX_Shdr*elf_get_shdr(char*_base, int i)
{
  ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  return (ElfXX_Shdr*)(_base + _ehdr->e_shoff + i * _ehdr->e_shentsize);
}

char*elf_get_section_name(char*_base, ElfXX_Shdr*_shdr)
{
  ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  ElfXX_Shdr*strtab_hdr = elf_get_shdr(_base, _ehdr->e_shstrndx);
  char*strtab_base = _base + strtab_hdr->sh_offset;
  return (strtab_base + _shdr->sh_name);
}

static ElfXX_Shdr*elf_get_section_bytype(char*_base, ElfXX_Word type)
{
  int j;
  ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  for(j = 0; j < _ehdr->e_shnum; j++)
    {
      ElfXX_Shdr*_shdr = elf_get_shdr(_base, j);
      if(_shdr->sh_type == type)
	return _shdr;
    }
  return NULL;
}

static ElfXX_Shdr*elf_get_section_byname(char*_base, const char*name)
{
  int j;
  ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  for(j = 0; j < _ehdr->e_shnum; j++)
    {
      ElfXX_Shdr*_shdr = elf_get_shdr(_base, j);
      const char*n = elf_get_section_name(_base, _shdr);
      if(strcmp(name, n) == 0)
	return _shdr;
    }
  return NULL;
}

/** Get a program header from its index */
static ElfXX_Phdr*elf_get_phdr(char*_base, int i)
{
  const ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  return (ElfXX_Phdr*)(_base + _ehdr->e_phoff + i * _ehdr->e_phentsize);
}

/** find a '_DYNAMIC' entry for a given tag */
static ElfXX_Dyn*elf_get_dynamic_entry(char*_base, ElfXX_Sword tag)
{
  int i;
  const ElfXX_Ehdr*_ehdr = (ElfXX_Ehdr*)_base;
  ElfXX_Phdr*dynamic_phdr = NULL;
  for(i = 0; i < _ehdr->e_phnum; i++)
    {
      ElfXX_Phdr*phdr = elf_get_phdr(_base, i);
      if(phdr->p_type == PT_DYNAMIC)
	{
	  dynamic_phdr = phdr;
	  break;
	}
    }
  ElfXX_Dyn*_DYNAMIC = (ElfXX_Dyn*)(_base + dynamic_phdr->p_offset);
  for(i = 0; _DYNAMIC[i].d_tag != DT_NULL ; i++)
    {
      if(_DYNAMIC[i].d_tag == tag)
	return &_DYNAMIC[i];
    }
  return NULL;
}

/** The ELF symbol Sys V hashing function */
static unsigned long elf_hash(const unsigned char*name)
{
  unsigned long h = 0, g = 0;
  while(*name)
    {
      h = (h << 4) + *name++;
      if((g = h & 0xf0000000))
	h ^= g >> 24;
      h &= ~g;
    }
  return h;
}

/** The ELF symbol GNU hashing function */
static unsigned long elf_gnu_hash(const unsigned char*name)
{
  unsigned long h = 5381;
  unsigned char c;
  while ((c = *name++) != '\0')
    {
      h = (h << 5) + h + c;
    }
  return h & 0xffffffff;
}

/** Compute the gap to insert in the ELF file (including padding for alignment)
 */
static unsigned long elfwrap_compute_gap(void*base)
{
  const ElfXX_Ehdr*ehdr = (ElfXX_Ehdr*)base;
  unsigned long gap = 32768;
  /* TODO: check that it is enough for .dynstr and .hash */
  int i;
  for(i = 0; i < ehdr->e_phnum; i++)
    {
      ElfXX_Phdr*phdr = elf_get_phdr(base, i);
      if(phdr->p_type == PT_LOAD)
	{
	  const unsigned long align = (phdr->p_align > 1)?phdr->p_align:PAGE_SIZE;
	  if(gap % align != 0)
	    {
	      gap += align - (gap % align);
	    }
	  assert(gap % align == 0);
	  assert(gap % PAGE_SIZE == 0);
	}
    }
  return gap;
}

/** re-builds a full SysV-compliant symbol hashtable.
 */
static void elfwrap_rebuild_hashtable_sysv(void*base, ElfXX_Word*hash_base)
{
  int i;
  unsigned long offset;
  long int nbucket = hash_base[0];
  long int nchain  = hash_base[1];
  ElfXX_Word*bucket = &hash_base[2];
  ElfXX_Word*chain  = &hash_base[2 + nbucket];
  ElfXX_Shdr*dynsyms_shdr = elf_get_section_bytype(base, SHT_DYNSYM);
  ElfXX_Shdr*dynstr_shdr  = elf_get_shdr(base, dynsyms_shdr->sh_link);
  
  printf("- rebuild hash table- nbucket=%ld; nchain=%ld (%ld symbols in section .dynsym)\n",
	 nbucket, nchain, (long)(dynsyms_shdr->sh_size / dynsyms_shdr->sh_entsize));
  for(i = 0 ; i < nbucket ; i++)
    bucket[i] = STN_UNDEF;
  for(i = 0 ; i < nchain ; i++)
    chain[i] = STN_UNDEF;
  printf("- hashing...\n");
  ElfXX_Word k = 0;
  for(offset = 0; offset < dynsyms_shdr->sh_size; offset += dynsyms_shdr->sh_entsize)
    {
      ElfXX_Sym*sym = (ElfXX_Sym*)(base + dynsyms_shdr->sh_offset + offset);
      unsigned char*symbol = (unsigned char*)(base + dynstr_shdr->sh_offset + sym->st_name);
      unsigned long x = elf_hash(symbol);
      if(bucket[x % nbucket] == STN_UNDEF)
	bucket[x % nbucket] = k;
      else
	{
	  ElfXX_Word y = bucket[x % nbucket];
	  while(chain[y] != STN_UNDEF)
	    y = chain[y];
	  chain[y] = k;
	}
      k++;
    }
}

/** builds a full SysV-compliant symbol hashtable from scratch
 */
static void elfwrap_create_hashtable_sysv(void*base, ElfXX_Word*hash_base, ElfXX_Shdr*hash_shdr)
{
  ElfXX_Shdr*dynsyms_shdr = elf_get_section_bytype(base, SHT_DYNSYM);
  long int nchain = dynsyms_shdr->sh_size / dynsyms_shdr->sh_entsize;
  long int nbucket = nchain * 2 + 1;
  printf("- creating full SysV hash table- nbucket=%ld; nchain=%ld (%ld symbols in section .dynsym)\n",
	 nbucket, nchain, (long)(dynsyms_shdr->sh_size / dynsyms_shdr->sh_entsize));
  hash_base[0] = nbucket;
  hash_base[1] = nchain;
  elfwrap_rebuild_hashtable_sysv(base, hash_base);

  const long new_offset = (void*)hash_base - base;
  const long shift = new_offset - hash_shdr->sh_offset;
  char*hashname = elf_get_section_name(base, hash_shdr);
  if(strcmp(hashname, ".hash") != 0)
    {
      strcpy(hashname, ".hash");
    }
  hash_shdr->sh_type = SHT_HASH;
  hash_shdr->sh_offset += shift;
  hash_shdr->sh_addr   += shift;

  ElfXX_Dyn*d = elf_get_dynamic_entry(base, DT_HASH);
  if(d)
    {
      printf("- adjusting .hash ptr in _DYNAMIC segment\n");
    }
  else
    {
#ifdef DT_GNU_HASH
      d = elf_get_dynamic_entry(base, DT_GNU_HASH);
      if(d)
	{
	  printf("- converting .gnu.hash in _DYNAMIC segment into .hash\n");
	}
#endif
    }
  if(!d)
    {
      fprintf(stderr, "elfwrap: cannot register hashtable in _DYNAMIC segment.\n");
      abort();
    }
  d->d_un.d_ptr = hash_shdr->sh_addr;
  d->d_tag = DT_HASH;
}


/** lists ELF content to screen for debug.
 */
static void elfwrap_listcontent(char*base)
{
  ElfXX_Ehdr*ehdr = (ElfXX_Ehdr*)base;
  int i;
  /* ELF header */
  printf("** ELF headers\n");
  printf("- machine: 0x%02x\n", ehdr->e_machine);
  printf("- section header: offset=0x%08lX; ends=0x%08lX\n", (unsigned long)ehdr->e_shoff,
	 (unsigned long)ehdr->e_shoff+ehdr->e_shnum*ehdr->e_shentsize);
  printf("- program header: offset=0x%08lX; ends=0x%08lX\n", (unsigned long)ehdr->e_phoff,
	 (unsigned long)ehdr->e_phoff+ehdr->e_phnum*ehdr->e_phentsize);

  /* Sections headers */
  printf("** Listing sections\n");
  printf("section | ____________name | type_________________ | vaddr________________ | offset_______________ | ____size | _align \n");
  for(i = 0; i < ehdr->e_shnum; i++)
    {
      ElfXX_Shdr*shdr = elf_get_shdr(base, i);
      printf(" #%2d    | %16s | 0x%08lX (%8s) | 0x%08lX:0x%08lX | 0x%08lX:0x%08lX | %8lX | 0x%04lX\n", i, 
	     elf_get_section_name(base, shdr),
	     (unsigned long)shdr->sh_type, (shdr->sh_type<12?sh_types[shdr->sh_type]:"--"), 
	     (unsigned long)shdr->sh_addr,  (unsigned long)shdr->sh_addr+shdr->sh_size,
	     (unsigned long)shdr->sh_offset, (unsigned long)shdr->sh_offset+shdr->sh_size, (unsigned long)shdr->sh_size,
	     (unsigned long)shdr->sh_addralign);
    }

  /* Program header */
  printf("** Listing segments\n");
  printf("segment | type__________________ | vaddr________________ | ___vsize | offset_______________ | ___fsize | _align \n");
  for(i = 0; i < ehdr->e_phnum; i++)
    {
      const ElfXX_Phdr*phdr = elf_get_phdr(base, i);
      printf(" #%2d    | 0x%08lX (_%8s) | 0x%08lX:0x%08lX | %8lX | 0x%08lX:0x%08lX | %8lX | 0x%04lX\n", i,
	     (unsigned long)phdr->p_type, (phdr->p_type<7?ph_types[phdr->p_type]:"--"), 
	     (unsigned long)phdr->p_vaddr,  (unsigned long)phdr->p_vaddr + phdr->p_memsz, (unsigned long)phdr->p_memsz,
	     (unsigned long)phdr->p_offset, (unsigned long)phdr->p_offset+phdr->p_filesz, (unsigned long)phdr->p_filesz,
	     (unsigned long)phdr->p_align);
    }
}

static void elfwrap_usage(const char*name)
{
  fprintf(stderr, "usage: %s <filename>\n", name);
  fprintf(stderr, "   <filename>  the ELF object to wrap (must be writable).\n");
}

int main(int argc, char**argv)
{
  if(argc != 2)
    {
      elfwrap_usage(argv[0]);
      exit(1);
    }
  if(strcmp(argv[1], "-h") == 0 ||
     strcmp(argv[1], "--help") == 0)
    {
      elfwrap_usage(argv[0]);
      exit(0);
    }
  /* ** file init */
  const char*filename = argv[1];
  int fd = open(filename, O_RDWR);
  if(fd == -1)
    {
      fprintf(stderr, "%s: file '%s' cannot be opened (%s).\n", argv[0], filename, strerror(errno));
      exit(1);
    }
  int rc;
  struct stat s;
  rc = fstat(fd, &s);
  unsigned int size = s.st_size;
  char*base = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
  if(!base)
    {
      fprintf(stderr, "%s: file '%s' is not readable (%s).\n", argv[0], filename, strerror(errno));
      exit(2);
    }

  /* ** sanity checks */
  ElfXX_Ehdr*ehdr = (ElfXX_Ehdr*)base;
  if(! (ehdr->e_ident[EI_MAG0] == 0x7f &&
	ehdr->e_ident[EI_MAG1] == 'E'  &&
	ehdr->e_ident[EI_MAG2] == 'L'  &&
	ehdr->e_ident[EI_MAG3] == 'F') )
    {
      fprintf(stderr, "%s: file '%s' is not an ELF binary.\n", argv[0], filename);
      exit(3);
    }
#if ( SIZEOF_LONG == 4 )
  printf("%s: compiled for 32 bits ELF.\n", argv[0]);
  if(ehdr->e_ident[EI_CLASS] != ELFCLASS32)
    {
      fprintf(stderr, "%s: file '%s' is not a 32 bits ELF binary.\n", argv[0], filename);
      exit(3);
    }
#elif ( SIZEOF_LONG == 8 )
  printf("%s: compiled for 64 bits ELF.\n", argv[0]);
  if(ehdr->e_ident[EI_CLASS] != ELFCLASS64)
    {
      fprintf(stderr, "%s: file '%s' is not a 64 bits ELF binary.\n", argv[0], filename);
      exit(3);
    }
#endif
  if(ehdr->e_type != ET_DYN)
    {
      fprintf(stderr, "%s: file '%s' is not a dynamic shared object.\n", argv[0], filename);
    }

  printf("%s: wrapping %s\n", argv[0], filename);
  printf("- page size = %ld\n", (long)PAGE_SIZE);

  /* show debugging info */
  elfwrap_listcontent(base);

  const char*note_patched = ".note.patched";
  if(elf_get_section_byname(base, note_patched) != NULL)
  {
    fprintf(stderr, "%s: library %s already patched.\n", argv[0], filename);
    exit(4);
  }

  /* Calculate gap */
  unsigned long gap = elfwrap_compute_gap(base);

  /* ** Grow the file */
  munmap(base, size);
  printf("** Growing file %s by %lu bytes\n", filename, gap);
  size += gap;
  rc = ftruncate(fd, size);
  if(rc)
    {
      fprintf(stderr, "%s: cannot extend file %s.\n", argv[0], filename);
      exit(5);
    }
  base = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if(!base)
    {
      fprintf(stderr, "%s: file '%s' is not writable.\n", argv[0], filename);
      exit(6);
    }
  ehdr = (ElfXX_Ehdr*)base;

  /* Extend segment containing '.dynstr' and move following segments */
  printf("- looking for _LOAD segment containing .dynstr\n");
  ElfXX_Shdr*dynsyms_shdr = elf_get_section_bytype(base, SHT_DYNSYM);
  if(dynsyms_shdr == NULL)
    {
      fprintf(stderr, "%s: cannot find _DYNSYM section.\n", argv[0]);
      abort();
    }
  ElfXX_Shdr*dynstr_shdr = elf_get_shdr(base, dynsyms_shdr->sh_link);
  if(dynstr_shdr == NULL || dynstr_shdr->sh_type != SHT_STRTAB)
    {
      fprintf(stderr, "%s: cannot find section with name '.dynstr' and type 'STRTAB'.\n", argv[0]);
      abort();
    }
  int i;
  unsigned long breakpoint = 0;
  for(i = 0; i < ehdr->e_phnum; i++)
    {
      ElfXX_Phdr*phdr = elf_get_phdr(base, i);
      if(phdr->p_type == PT_LOAD &&
	 dynstr_shdr->sh_offset >= phdr->p_offset &&
	 dynstr_shdr->sh_offset <= phdr->p_offset + phdr->p_filesz)
	{
	  breakpoint = phdr->p_offset + phdr->p_filesz;
	  printf("- extending segment #%d (offset=%lu bytes)- breakpoint=0x%08lX; align=0x%X\n", i, gap, breakpoint, (unsigned)phdr->p_align);
	  phdr->p_filesz += gap;
	  phdr->p_memsz  += gap;
	  phdr->p_align = PAGE_SIZE;
	  memmove(base + breakpoint + gap, 
		  base + breakpoint,
		  size - (gap + breakpoint));
	  memset(base + breakpoint, 0, gap);
	  break;
	}
    }
  if(breakpoint == 0)
    {
      fprintf(stderr, "%s: non-standard ELF layout detected. '.dynstr' section found in no _LOAD segment. Cannot patch.\n", argv[0]);
      exit(7);
    }

  /* Adjust offsets in ELF hdr */
  if(ehdr->e_entry >= breakpoint)
    {
      printf("- adjusting entry point in ELF header\n");
      ehdr->e_entry += gap;
    }
  if(ehdr->e_phoff >= breakpoint)
    {
      printf("- adjusting program header offset in ELF header\n");
      ehdr->e_phoff += gap;
    }
  if(ehdr->e_shoff >= breakpoint)
    {
      printf("- adjusting section header offset in ELF header\n");
      ehdr->e_shoff += gap;
    }

  /* Calculate new segment boundaries */
  for(i = 0; i < ehdr->e_phnum; i++)
    {
      ElfXX_Phdr*phdr = elf_get_phdr(base, i);
      if(phdr->p_offset >= breakpoint)
	phdr->p_offset += gap;
    }

  /* Calculate new section boundaries */
  for(i = 0; i < ehdr->e_shnum; i++)
    {
      ElfXX_Shdr*shdr = elf_get_shdr(base, i);
      if(shdr->sh_offset >= breakpoint)
	shdr->sh_offset += gap;
    }

  /* Move .dynstr */
  printf("- moving .dynstr section at end of segment\n");
  dynsyms_shdr = elf_get_section_bytype(base, SHT_DYNSYM);
  dynstr_shdr = elf_get_shdr(base, dynsyms_shdr->sh_link);
  char*old_dynstr_base = base + dynstr_shdr->sh_offset;
  char*new_dynstr_base = base + breakpoint;
  const unsigned long dynstr_shift = new_dynstr_base - old_dynstr_base;
  printf("- .dynstr shift=0x%lX (%p -> %p)\n", dynstr_shift, old_dynstr_base, new_dynstr_base);
  memcpy(new_dynstr_base, old_dynstr_base, dynstr_shdr->sh_size);
  dynstr_shdr->sh_offset += dynstr_shift;
  dynstr_shdr->sh_addr   += dynstr_shift;

  /* Translating dynamic symbols */
  unsigned long dynstr_offset = dynstr_shdr->sh_size + 1; /* used to allocate new symbols */
  printf("** Translating symbols\n");

  printf("- looking for symbol version table .version\n");
  ElfXX_Shdr*versym_shdr = elf_get_section_bytype(base, SHT_GNU_versym);
  
  unsigned long sym_offset = 0;
  unsigned long ver_offset = 0;
  for(sym_offset = 0, ver_offset = 0;
      sym_offset < dynsyms_shdr->sh_size;
      sym_offset += dynsyms_shdr->sh_entsize, ver_offset += versym_shdr->sh_entsize)
    {
      ElfXX_Sym*sym = (ElfXX_Sym*)(base + dynsyms_shdr->sh_offset + sym_offset);
      ElfXX_Half*ver = (versym_shdr == NULL) ? NULL : ((ElfXX_Half*)(base + versym_shdr->sh_offset + ver_offset));
      if((ELFXX_ST_TYPE(sym->st_info) == STT_FUNC) &&
	 (sym->st_shndx == SHN_UNDEF))
	{
	  char*symbol = base + dynstr_shdr->sh_offset + sym->st_name;
	  const int version = (ver == NULL) ? 1 : (int)*ver;
	  struct elfwrap_alias_s*e = NULL;
	  for(e = &elfwrap_alias_table[0]; e->sym != NULL; e++)
	    {
	      if(symbol && strcmp(e->sym, symbol) == 0)
		{
		  printf("- aliasing: %24s -> %s\n", e->sym, e->alias);
		  if(version > 1)
		    {
		      printf("  reset symbol version to 1 (GLOBAL)\n");
		      *ver = 1;
		    }
		  
		  strcpy(base + dynstr_shdr->sh_offset + dynstr_offset, e->alias);
		  sym->st_name = dynstr_offset;
		  dynstr_offset += strlen(e->alias) + 1;
		  break;
		}
	    }
	}
    }
  dynstr_shdr->sh_size = dynstr_offset;

  /* adjust .dynstr in _DYNAMIC segment */
  printf("- adjusting .dynstr ptr and size in _DYNAMIC segment\n");
  ElfXX_Dyn*d = elf_get_dynamic_entry(base, DT_STRTAB);
  d->d_un.d_ptr += dynstr_shift;
  d = elf_get_dynamic_entry(base, DT_STRSZ);
  d->d_un.d_val = dynstr_offset;

  /* Hashtable */
  printf("** Rewriting dynamic symbols hash table\n");
  d = elf_get_dynamic_entry(base, DT_HASH);
  const ElfXX_Addr dyn_hash_ptr = (d != NULL)?d->d_un.d_ptr:0;
  printf("- SysV hash table ptr in _DYNAMIC: %p\n", (void*)dyn_hash_ptr);
#ifdef DT_GNU_HASH
  d = elf_get_dynamic_entry(base, DT_GNU_HASH);
  const ElfXX_Addr dyn_gnuhash_ptr = (d != NULL)?d->d_un.d_ptr:0;
  printf("- GNU hash table ptr in _DYNAMIC: %p\n", (void*)dyn_gnuhash_ptr);
#endif

  ElfXX_Shdr*hash_shdr = elf_get_section_bytype(base, SHT_HASH);
#ifdef SHT_GNU_HASH
  ElfXX_Shdr*gnuhash_shdr = elf_get_section_bytype(base, SHT_GNU_HASH);
#else
  ElfXX_Shdr*gnuhash_shdr = NULL;
#endif
  if(gnuhash_shdr && !hash_shdr)
    {
      printf("** Existing hashtable is GNU style. Creating new SysV-compliant hashtable.\n");
      const long new_offset = dynstr_shdr->sh_offset + dynstr_shdr->sh_size;
      ElfXX_Word*new_hash_table = (ElfXX_Word*)(base + new_offset);
      printf("- new hash offset = 0x%lx\n", new_offset);
      elfwrap_create_hashtable_sysv(base, new_hash_table, gnuhash_shdr);
    }
  else if(!gnuhash_shdr && !hash_shdr)
    {
      fprintf(stderr, "elfwrap: non-standard ELF layout detected. Cannot get any .hash section.\n");
      exit(12);
    }
  else if(hash_shdr)
    {
      if(gnuhash_shdr)
	{
	  printf("- removing GNU hash table: removing section '.gnu.hash'\n");
	  char*gnuhash = elf_get_section_name(base, gnuhash_shdr);
	  if(gnuhash && strcmp(".gnu.hash", gnuhash) == 0)
	    {
	      strcpy(gnuhash, ".old.hash");
	      gnuhash_shdr->sh_type = SHN_UNDEF;
	    }
	  else
	    {
	      printf("- section '.gnu.hash' not found!\n");
	    }
	}
      ElfXX_Word*hash_base = (ElfXX_Word*)(base + hash_shdr->sh_offset);
      if(hash_shdr->sh_offset != dyn_hash_ptr)
	{
	  fprintf(stderr, "elfwrap: WARNING- inconsistency detected in hashtable offset- in section: %p; in _DYNAMIC segment: %p. Library is likely pre-linked.\n",
		  (void*)hash_shdr->sh_offset, (void*)dyn_hash_ptr);
	}
      elfwrap_rebuild_hashtable_sysv(base, hash_base);
    }

  printf("- done.\n");

  /* show debugging info */
  elfwrap_listcontent(base);

  printf("** %s wrapping ok.\n", filename);
  close(fd);

  return 0;
}
