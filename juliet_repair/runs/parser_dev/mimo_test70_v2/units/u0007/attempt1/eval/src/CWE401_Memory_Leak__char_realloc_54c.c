#include "std_testcase.h"

#include <wchar.h>


void CWE401_Memory_Leak__char_realloc_54d_badSink(char * data);

void CWE401_Memory_Leak__char_realloc_54c_badSink(char * data)
{
    CWE401_Memory_Leak__char_realloc_54d_badSink(data);
}
