#include <stdlib.h>

int double_free(int argc)
{
    int *values = (int *)malloc(4 * sizeof(int));
    if (values == NULL) {
        return 1;
    }
    values[0] = argc;
    free(values);
    free(values);
    return 0;
}

int main(int argc, char **argv)
{
    (void)argv;
    return double_free(argc);
}
