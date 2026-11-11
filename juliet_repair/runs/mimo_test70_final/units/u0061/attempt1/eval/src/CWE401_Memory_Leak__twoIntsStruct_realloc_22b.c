#include "std_testcase.h"

#include <wchar.h>


extern int CWE401_Memory_Leak__twoIntsStruct_realloc_22_badGlobal;

void CWE401_Memory_Leak__twoIntsStruct_realloc_22_badSink(twoIntsStruct * data)
{
    if(CWE401_Memory_Leak__twoIntsStruct_realloc_22_badGlobal)
    {
        free(data);
        data = NULL;
    }
}
