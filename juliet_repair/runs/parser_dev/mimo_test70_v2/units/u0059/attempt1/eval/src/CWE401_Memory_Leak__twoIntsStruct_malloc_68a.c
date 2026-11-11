#include "std_testcase.h"

#include <wchar.h>

twoIntsStruct * CWE401_Memory_Leak__twoIntsStruct_malloc_68_badData;


void CWE401_Memory_Leak__twoIntsStruct_malloc_68b_badSink();

void CWE401_Memory_Leak__twoIntsStruct_malloc_68_bad()
{
    twoIntsStruct * data;
    data = NULL;

    data = (twoIntsStruct *)malloc(100*sizeof(twoIntsStruct));
    if (data == NULL) {exit(-1);}

    data[0].intOne = 0;
    data[0].intTwo = 0;
    printStructLine(&data[0]);
    CWE401_Memory_Leak__twoIntsStruct_malloc_68_badData = data;
    CWE401_Memory_Leak__twoIntsStruct_malloc_68b_badSink();
}
