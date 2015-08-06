# elfhash


elfhash is a utility to manipulate hash table of ELF file.

#Features:

0, Architecture indepent, That means you can handle 32bit arm ELF in x86/x86_64 platform.

1, Convert GNU style hashtable in ELF to sysV style.

2, Rebuild sysv hashtable, if you change ELF dynamic symbols manually, you may need re-hash it.

3, Rename symbols to new name as same length. 
   "The same length" is a limition: 
    If new symbol name has different length, we need handle so many offset problem.


#Build:

  $make

  $sudo make install

  It will install 'elfhash' to handle both 32bit and 64bit ELF.

#Usage:

  $elfhash <elf file>    : convert gnu style hash to sysv style if it exists.

  $elfhash -r <elf file> : rebuild sysv hash.

  $elfhash -f old_symbol -t new_symbol <elf file> :rename old symbol name to new name

  $elfhash -l <elf file> : list the contents of elf

#NOTE:

  !!!!!!!!!!!!!!!!!!!!!!!!!!!!
  DO not use it to manipulate system libraries, it is dangerous!!!!

#Thanks:

1.some codes come from PadicoTM project.

svn co svn://scm.gforge.inria.fr/svn/pm2/trunk

2.elf.h comes from elfutils without modifications.

