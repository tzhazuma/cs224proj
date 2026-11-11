#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__twoIntsStruct_malloc_33
{


void bad()
{
    twoIntsStruct * data;
    twoIntsStruct * &dataRef = data;
    data = NULL;

    data = (twoIntsStruct *)malloc(100*sizeof(twoIntsStruct));
    if (data == NULL) {exit(-1);}

    data[0].intOne = 0;
    data[0].intTwo = 0;
    printStructLine(&data[0]);
    {
        twoIntsStruct * data = dataRef;

        ;
    }
    free(data);
}


}
