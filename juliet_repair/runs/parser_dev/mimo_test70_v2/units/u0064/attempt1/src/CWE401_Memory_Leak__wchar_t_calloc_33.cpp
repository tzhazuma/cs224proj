#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__wchar_t_calloc_33
{


void bad()
{
    wchar_t * data;
    wchar_t * &dataRef = data;
    data = NULL;

    data = (wchar_t *)calloc(100, sizeof(wchar_t));
    if (data == NULL) {exit(-1);}

    wcscpy(data, L"A String");
    printWLine(data);
    {
        wchar_t * data = dataRef;

        free(data);
    }
}


}
