#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_wchar_t_01
{


void bad()
{
    wchar_t * data;
    data = NULL;

    data = new wchar_t;

    *data = L'A';
    printHexCharLine((char)*data);

    delete data;
}


}
