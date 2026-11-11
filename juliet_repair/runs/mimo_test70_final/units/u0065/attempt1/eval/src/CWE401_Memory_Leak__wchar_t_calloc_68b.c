#include "std_testcase.h"

#include <wchar.h>
#include <stdlib.h>

extern wchar_t * CWE401_Memory_Leak__wchar_t_calloc_68_badData;


void CWE401_Memory_Leak__wchar_t_calloc_68b_badSink()
{
    wchar_t * data = CWE401_Memory_Leak__wchar_t_calloc_68_badData;

    free(data);
}
