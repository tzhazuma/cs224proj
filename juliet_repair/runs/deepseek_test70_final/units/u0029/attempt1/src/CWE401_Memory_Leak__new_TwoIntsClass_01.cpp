#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_TwoIntsClass_01
{


void bad()
{
    TwoIntsClass * data;
    data = NULL;

    data = new TwoIntsClass;

    data->intOne = 0;
    data->intTwo = 0;
    printIntLine(data->intOne);
    printIntLine(data->intTwo);

    delete data;
}


}
