DESTDIR=
all:
	gcc -c elfhash.c -o elfhash32.o -DELFCLASS=32
	gcc -c elfhash.c -o elfhash64.o -DELFCLASS=64
	gcc -c main.c -o main.o
	gcc -o elfhash main.o elfhash32.o elfhash64.o	
install: all
	mkdir -p $(DESTDIR)/usr/bin
	install -m 0755 elfhash $(DESTDIR)/usr/bin
clean:
	rm -rf *.o elfhash
