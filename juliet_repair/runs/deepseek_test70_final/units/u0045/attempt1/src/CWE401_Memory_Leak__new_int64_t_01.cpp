#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_int64_t_01
{


void bad()
{
    int64_t * data;
    data = NULL;

    data = new int64_t;

    *data = 5LL;
    printLongLongLine(*data);

    delete data;
}


}
