#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_twoIntsStruct_54
{


void badSink_e(twoIntsStruct * data);

void badSink_d(twoIntsStruct * data)
{
    badSink_e(data);
}


}
