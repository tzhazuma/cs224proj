#include <stdlib.h>

int no_leak(int argc)
{
    int *values = (int *)malloc(8 * sizeof(int));
    if (values == NULL) {
        return 1;
    }
    values[0] = argc;
    int result = values[0];
    free(values);
    return result;
}

int main(int argc, char **argv)
{
    (void)argv;
    return no_leak(argc);
}
