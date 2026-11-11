#include "std_testcase.h"

#include <wchar.h>


void CWE401_Memory_Leak__wchar_t_calloc_01_bad()
{
    wchar_t * data;
    data = NULL;

    data = (wchar_t *)calloc(100, sizeof(wchar_t));
    if (data == NULL) {exit(-1);}

    wcscpy(data, L"A String");
    printWLine(data);

    ;
}
