#include "std_testcase.h"

#include <wchar.h>


extern int CWE401_Memory_Leak__int_malloc_22_badGlobal;

void CWE401_Memory_Leak__int_malloc_22_badSink(int * data)
{
    if(CWE401_Memory_Leak__int_malloc_22_badGlobal)
    {

        ;
    }
}
