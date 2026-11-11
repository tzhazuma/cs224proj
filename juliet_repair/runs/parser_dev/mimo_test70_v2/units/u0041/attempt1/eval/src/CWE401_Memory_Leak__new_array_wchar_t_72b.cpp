#include "std_testcase.h"
#include <vector>

#include <wchar.h>

using namespace std;

namespace CWE401_Memory_Leak__new_array_wchar_t_72
{


void badSink(vector<wchar_t *> dataVector)
{

    wchar_t * data = dataVector[2];

    delete [] data;
}


}
