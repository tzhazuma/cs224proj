#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_array_char_22
{


int badGlobal = 0;

void badSink(char * data);

void bad()
{
    char * data;
    data = NULL;

    data = new char[100];

    strcpy(data, "A String");
    printLine(data);
    badGlobal = 1;
    badSink(data);
}


}
