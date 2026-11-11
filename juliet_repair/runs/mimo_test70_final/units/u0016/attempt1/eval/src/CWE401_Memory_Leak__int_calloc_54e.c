#include "std_testcase.h"

#include <wchar.h>


void CWE401_Memory_Leak__int_calloc_54e_badSink(int * data)
{
    free(data);
}
