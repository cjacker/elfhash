#include "helloWorld.h"
#include <stdio.h>
#include <string.h>
void JNICALL Java_helloWorld_SayHello(JNIEnv * env, jobject obj, jstring str)
{
    printf("Hello\n");
}


int test()
{
printf("ASFSAFAD\n");
}
