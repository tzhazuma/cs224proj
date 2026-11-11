#include "std_testcase.h"
#include <vector>

#include <wchar.h>

using namespace std;

namespace CWE401_Memory_Leak__new_char_72
{


void badSink(vector<char *> dataVector)
{

    char * data = dataVector[2];

    ;
}


}
