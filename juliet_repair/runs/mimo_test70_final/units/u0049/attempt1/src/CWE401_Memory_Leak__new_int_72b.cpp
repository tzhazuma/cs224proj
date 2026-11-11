#include "std_testcase.h"
#include <vector>

#include <wchar.h>

using namespace std;

namespace CWE401_Memory_Leak__new_int_72
{


void badSink(vector<int *> dataVector)
{

    int * data = dataVector[2];

    delete data;
}


}
