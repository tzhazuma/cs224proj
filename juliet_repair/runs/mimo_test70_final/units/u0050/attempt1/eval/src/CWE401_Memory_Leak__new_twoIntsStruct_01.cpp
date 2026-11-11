#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_twoIntsStruct_01
{


void bad()
{
    twoIntsStruct * data;
    data = NULL;

    data = new twoIntsStruct;

    data->intOne = 0;
    data->intTwo = 0;
    printStructLine(data);

    delete data;
    data = NULL;
}


}
