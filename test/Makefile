all:
	@gcc -Wl,--hash-style=gnu -shared -o libdll.so hello.c -I/usr/share/openjdk/include -I/usr/share/openjdk/include/linux -fPIC
	@#gcc -Wl,--hash-style=sysv -shared -o libdll.so hello.c -I/usr/share/openjdk/include -I/usr/share/openjdk/include/linux -fPIC
	@gcc -o main main.c -L. -ldll -I/usr/share/openjdk/include -I/usr/share/openjdk/include/linux
	@javac HelloWorld.java
clean:
	@rm -rf libdll.so* main *.class 
run: all
	@echo -e "\e[0;34m## Before elf patch, \e[0;31merror happened\e[0m"
	@java -Djava.library.path=. HelloWorld ||:
	@echo -e "\e[0;34m## Patch elf\e[0m"
	@../elfhash -f Java_helloWorld_SayHello -t Java_HelloWorld_SayHello libdll.so 
	@echo -e "\e[0;34m## After elf patch, expect result is \"Hello\"\e[0m"
	@java -Djava.library.path=. HelloWorld ||:
