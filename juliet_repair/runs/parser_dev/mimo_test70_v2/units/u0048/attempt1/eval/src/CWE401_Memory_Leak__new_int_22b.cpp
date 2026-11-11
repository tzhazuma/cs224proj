#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_int_22
{


extern int badGlobal;

void badSink(int * data)
{
    if(badGlobal)
    {

        delete data;
    }
}


}
