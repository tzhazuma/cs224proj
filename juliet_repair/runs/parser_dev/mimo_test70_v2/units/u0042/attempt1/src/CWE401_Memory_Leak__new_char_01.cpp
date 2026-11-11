#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_char_01
{


void bad()
{
    char * data;
    data = NULL;

    data = new char;

    *data = 'A';
    printHexCharLine(*data);

    delete [] data;
    data = NULL;
    ;
}


}
