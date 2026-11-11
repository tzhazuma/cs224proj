#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_array_int64_t_31
{


void bad()
{
    int64_t * data;
    data = NULL;

    data = new int64_t[100];

    data[0] = 5LL;
    printLongLongLine(data[0]);
    {
        int64_t * dataCopy = data;
        int64_t * data = dataCopy;

        ;
    }
    delete[] data;
}


}
