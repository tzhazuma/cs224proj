#include "std_testcase.h"

#include <wchar.h>


void CWE401_Memory_Leak__malloc_realloc_twoIntsStruct_18_bad()
{
    goto sink;
sink:
    {
        twoIntsStruct * data = (twoIntsStruct *)malloc(100*sizeof(twoIntsStruct));
        if (data == NULL) {exit(-1);}

        data[0].intOne = 0;
        data[0].intTwo = 0;
        printStructLine(&data[0]);

        twoIntsStruct * newData = (twoIntsStruct *)realloc(data, (130000)*sizeof(twoIntsStruct));
        if (newData != NULL)
        {
            data = newData;
            data[0].intOne = 1;
            data[0].intTwo = 1;
            printStructLine(&data[0]);
            free(data);
        }
        else
        {
            free(data);
        }
    }
}
