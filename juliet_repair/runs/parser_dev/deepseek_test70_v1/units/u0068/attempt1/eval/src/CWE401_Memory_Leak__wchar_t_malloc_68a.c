#include "std_testcase.h"

#include <wchar.h>

wchar_t * CWE401_Memory_Leak__wchar_t_malloc_68_badData;


void CWE401_Memory_Leak__wchar_t_malloc_68b_badSink();

void CWE401_Memory_Leak__wchar_t_malloc_68_bad()
{
    wchar_t * data;
    data = NULL;

    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (data == NULL) {exit(-1);}

    wcscpy(data, L"A String");
    printWLine(data);
    CWE401_Memory_Leak__wchar_t_malloc_68_badData = data;
    CWE401_Memory_Leak__wchar_t_malloc_68b_badSink();
    free(data);
    CWE401_Memory_Leak__wchar_t_malloc_68_badData = NULL;
}
