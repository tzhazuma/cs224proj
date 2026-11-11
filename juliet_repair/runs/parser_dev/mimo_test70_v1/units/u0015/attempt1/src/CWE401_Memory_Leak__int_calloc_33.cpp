#include "std_testcase.h"

#include <wchar.h>
#include <stdlib.h>

namespace CWE401_Memory_Leak__int_calloc_33
{


void bad()
{
    int * data;
    int * &dataRef = data;
    data = NULL;

    data = (int *)calloc(100, sizeof(int));
    if (data == NULL) {exit(-1);}

    data[0] = 5;
    printIntLine(data[0]);
    {
        int * data = dataRef;

        free(data);
    }
}


}
