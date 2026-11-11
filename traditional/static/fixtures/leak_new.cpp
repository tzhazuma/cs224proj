int may_leak_new(int argc)
{
    int *values = new int[8];
    values[0] = argc;
    if (argc > 0) {
        return values[0];
    }
    delete[] values;
    return 0;
}

int main(int argc, char **argv)
{
    (void)argv;
    return may_leak_new(argc);
}
