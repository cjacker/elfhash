#include <stdlib.h>
#include "helloWorld.h"
extern void test();
int main()
{
    test();
    jobject t;
    jstring s;
    Java_helloWorld_SayHello(NULL, t, s);
}
