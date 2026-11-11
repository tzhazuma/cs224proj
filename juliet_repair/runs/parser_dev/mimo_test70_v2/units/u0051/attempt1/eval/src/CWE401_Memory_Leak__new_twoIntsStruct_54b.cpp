#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_twoIntsStruct_54
{


void badSink_c(twoIntsStruct * data);

void badSink_b(twoIntsStruct * data)
{
    badSink_c(data);
}


}
