#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_array_twointsStruct_68
{

extern twoIntsStruct * badData;


void badSink()
{
    twoIntsStruct * data = badData;

    ;
}


}
