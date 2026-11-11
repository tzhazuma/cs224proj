#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__int64_t_realloc_33
{


void bad()
{
    int64_t * data;
    int64_t * &dataRef = data;
    data = NULL;

    data = (int64_t *)realloc(data, 100*sizeof(int64_t));
    if (data == NULL) {exit(-1);}

    data[0] = 5LL;
    printLongLongLine(data[0]);
    {
        int64_t * data = dataRef;

        free(data);
    }
}


}
