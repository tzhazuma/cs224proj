#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_TwoIntsClass_68
{

extern TwoIntsClass * badData;


void badSink()
{
    TwoIntsClass * data = badData;

    delete data;
    badData = NULL;
}


}
