#ifndef ELFHASH_H
#define ELFHASH_H
int is_32bit_elf(char *base);
int is_64bit_elf(char *base);

int is_valid_elf64(char *base);
int has_gnuhash64(char *base);
int rename_func64(char *base, const char *old_func, const char *new_func);
int rehash64(char *base);
int convert_gnu_to_sysv64(char *base, unsigned long size, unsigned long gap);
void elfhash_listcontent64(char* base);
unsigned long elfhash_compute_gap64(void*base);


int is_valid_elf32(char *base);
int has_gnuhash32(char *base);
int rename_func32(char *base, const char *old_func, const char *new_func);
int rehash32(char *base);
int convert_gnu_to_sysv32(char *base, unsigned long size, unsigned long gap);
void elfhash_listcontent32(char* base);
unsigned long elfhash_compute_gap32(void*base);
#endif
