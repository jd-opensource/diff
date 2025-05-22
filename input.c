#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>

int mm = 188;
struct A {
   int a;
   int b;
};

struct B {
   int m;
   struct A a;
};

__attribute((__annotate__(("bcf"))))
int bcftest(int* returunvalue, struct B *b){    
    printf("- :%f\n", 3.14);
    *returunvalue = b->m;
    int a = 1;
    for(a = 0; a < 10; a++){
        printf("%d\n", a);
    }
    printf("ref global: %d", mm);
    return a;
}

__attribute((__annotate__(("fla"))))
int flatest(int* returunvalue, struct B *b){    
    printf("- :%f\n", 3.14);
    *returunvalue = b->m;
    int a = 1;
    for(a = 0; a < 10; a++){
        printf("%d\n", a);
    }
    printf("stack size ====== : %x\n", stacksize);
    return 0;
}

int main(){
    struct B bb;
    bb.m = 0x99;
    int returunvalue;

    printf("==================================================================================\n");
    bcftest(&returunvalue, &bb);
    printf("hello: 0x%x\n", returunvalue);

    printf("==================================================================================\n");
    bb.m = 0x66;
    int ret2 = flatest(&returunvalue, &bb);
    printf("hello: 0x%x\n", returunvalue);
    return 0;
}

