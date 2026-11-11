#include <stdlib.h>
#include <string.h>

int may_leak(int argc, char **argv)
{
    char *buffer = (char *)malloc(32);
    if (buffer == NULL) {
        return 1;
    }
    if (argc > 1) {
        strncpy(buffer, argv[1], 31);
        buffer[31] = '\0';
        return (int)buffer[0];
    }
    free(buffer);
    return 0;
}

int main(int argc, char **argv)
{
    return may_leak(argc, argv);
}
