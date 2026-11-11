#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_array_wchar_t_31
{


void bad()
{
    wchar_t * data;
    data = NULL;

    data = new wchar_t[100];

    wcscpy(data, L"A String");
    printWLine(data);
    {
        wchar_t * dataCopy = data;
        wchar_t * data = dataCopy;

        ;
    }
}


}
