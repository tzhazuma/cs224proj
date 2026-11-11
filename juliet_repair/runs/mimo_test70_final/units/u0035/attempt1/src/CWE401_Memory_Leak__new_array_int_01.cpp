#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_array_int_01
{


void bad()
{
    int * data;
    data = NULL;

    data = new int[100];

    data[0] = 5;
    printIntLine(data[0]);

    delete [] data;
    data = NULL;
}


}
