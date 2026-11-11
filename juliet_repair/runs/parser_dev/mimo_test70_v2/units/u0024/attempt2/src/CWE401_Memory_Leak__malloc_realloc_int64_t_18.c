#include "std_testcase.h"

#include <wchar.h>


void CWE401_Memory_Leak__malloc_realloc_int64_t_18_bad()
{
    goto sink;
sink:
    {
        int64_t * data = (int64_t *)malloc(100*sizeof(int64_t));
        if (data == NULL) {exit(-1);}

        data[0] = 5LL;
        printLongLongLine(data[0]);

        int64_t * oldData = data;
        data = (int64_t *)realloc(data, (130000)*sizeof(int64_t));
        if (data != NULL)
        {
            if (data != oldData)
            {
                free(oldData);
            }
            data[0] = 10LL;
            printLongLongLine(data[0]);
            free(data);
        }
        else
        {
            free(oldData);
        }
    }
}
