#include <stdlib.h>

int leak_region(int argc)
{
    int *values = (int *)malloc(4 * sizeof(int));
    if (values == NULL) {
        return 1;
    }
    values[0] = argc;
    if (argc > 0) {
        return values[0];
    }
    free(values);
    return 0;
}

int clean_region(int argc)
{
    int *values = (int *)malloc(4 * sizeof(int));
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
    return leak_region(argc) + clean_region(argc);
}
