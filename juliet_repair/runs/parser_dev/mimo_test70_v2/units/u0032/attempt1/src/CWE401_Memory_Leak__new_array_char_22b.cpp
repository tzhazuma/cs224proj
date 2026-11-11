#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_array_char_22
{


extern int badGlobal;

void badSink(char * data)
{
    if(badGlobal)
    {

        delete[] data;
    }
}


}
