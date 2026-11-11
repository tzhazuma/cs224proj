#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_array_int_22
{


int badGlobal = 0;

void badSink(int * data);

void bad()
{
    int * data;
    data = NULL;

    data = new int[100];

    data[0] = 5;
    printIntLine(data[0]);
    badGlobal = 1;
    badSink(data);

    delete[] data;
}


}
