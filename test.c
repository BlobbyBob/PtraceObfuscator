#include <stdio.h>
#include <unistd.h>

#define PREFIX "test.c:%2i: "

extern char _start;

void printArray(char **arr) {
    int i = 0;
    while (arr[i] != NULL) {
        printf("%s\n", arr[i++]);
    }
}

int main(int argc, char **argv, char **envp) {

    printf(PREFIX "-> _start at 0x%016x\n", __LINE__, &_start);
    printf(PREFIX "-> main   at 0x%016x\n", __LINE__, &main);
    printf(PREFIX "-> Starting Test\n", __LINE__);

    for (char i = 65; i < 75; i++) {
        putchar(i);
    }
    putchar('\n');

    printArray(argv);
    printArray(envp);

    printf(PREFIX "-> Jumped\n", __LINE__);
    printf(PREFIX "-> Exiting\n", __LINE__);
    return 0;
}
