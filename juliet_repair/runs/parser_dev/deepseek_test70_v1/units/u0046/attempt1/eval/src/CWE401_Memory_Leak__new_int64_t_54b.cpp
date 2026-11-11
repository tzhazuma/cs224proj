#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_int64_t_54
{


void badSink_c(int64_t * data);

void badSink_b(int64_t * data)
{
    badSink_c(data);
}


}
