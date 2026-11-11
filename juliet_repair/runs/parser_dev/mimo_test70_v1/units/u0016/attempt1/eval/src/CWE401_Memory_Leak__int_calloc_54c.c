#include "std_testcase.h"

#include <wchar.h>


void CWE401_Memory_Leak__int_calloc_54d_badSink(int * data);

void CWE401_Memory_Leak__int_calloc_54c_badSink(int * data)
{
    CWE401_Memory_Leak__int_calloc_54d_badSink(data);
}
