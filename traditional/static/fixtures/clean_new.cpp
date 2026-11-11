int no_leak_new(int argc)
{
    int *values = new int[8];
    values[0] = argc;
    int result = values[0];
    delete[] values;
    return result;
}

int main(int argc, char **argv)
{
    (void)argv;
    return no_leak_new(argc);
}
