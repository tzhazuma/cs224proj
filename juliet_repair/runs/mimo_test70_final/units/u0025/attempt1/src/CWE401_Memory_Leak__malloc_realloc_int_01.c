#include "std_testcase.h"

#include <wchar.h>


void CWE401_Memory_Leak__malloc_realloc_int_01_bad()
{
    {
        int * data = (int *)malloc(100*sizeof(int));
        if (data == NULL) {exit(-1);}

        data[0] = 5;
        printIntLine(data[0]);

        int * oldData = data;
        data = (int *)realloc(data, (130000)*sizeof(int));
        if (data != NULL)
        {
            data[0] = 10;
            printIntLine(data[0]);
            free(data);
        }
        else
        {
            free(oldData);
        }
    }
}
