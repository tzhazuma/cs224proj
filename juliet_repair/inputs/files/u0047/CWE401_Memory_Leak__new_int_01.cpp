#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_int_01
{


void bad()
{
    int * data;
    data = NULL;

    data = new int;

    *data = 5;
    printIntLine(*data);

    ;
}


}
