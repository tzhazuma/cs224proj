#include "std_testcase.h"

#include <wchar.h>


int CWE401_Memory_Leak__twoIntsStruct_realloc_22_badGlobal = 0;

void CWE401_Memory_Leak__twoIntsStruct_realloc_22_badSink(twoIntsStruct * data);

void CWE401_Memory_Leak__twoIntsStruct_realloc_22_bad()
{
    twoIntsStruct * data;
    data = NULL;

    data = (twoIntsStruct *)realloc(data, 100*sizeof(twoIntsStruct));
    if (data == NULL) {exit(-1);}

    data[0].intOne = 0;
    data[0].intTwo = 0;
    printStructLine(&data[0]);
    CWE401_Memory_Leak__twoIntsStruct_realloc_22_badGlobal = 1;
    CWE401_Memory_Leak__twoIntsStruct_realloc_22_badSink(data);
    free(data);
}
