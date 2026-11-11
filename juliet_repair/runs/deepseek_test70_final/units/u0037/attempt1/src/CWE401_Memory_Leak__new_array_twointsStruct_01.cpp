#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_array_twointsStruct_01
{


void bad()
{
    twoIntsStruct * data;
    data = NULL;

    data = new twoIntsStruct[100];

    data[0].intOne = 0;
    data[0].intTwo = 0;
    printStructLine(&data[0]);

    ;

    delete[] data;
}


}
