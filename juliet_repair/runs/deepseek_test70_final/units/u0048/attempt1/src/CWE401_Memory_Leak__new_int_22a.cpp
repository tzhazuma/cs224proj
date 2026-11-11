#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_int_22
{


int badGlobal = 0;

void badSink(int * data);

void bad()
{
    int * data;
    data = NULL;

    data = new int;

    *data = 5;
    printIntLine(*data);
    badGlobal = 1;
    badSink(data);
    delete data;
}


}
