#include "std_testcase.h"
#include <vector>

#include <wchar.h>

using namespace std;

namespace CWE401_Memory_Leak__new_int_72
{


void badSink(vector<int *> dataVector);

void bad()
{
    int * data;
    vector<int *> dataVector;
    data = NULL;

    data = new int;

    *data = 5;
    printIntLine(*data);

    dataVector.insert(dataVector.end(), 1, data);
    dataVector.insert(dataVector.end(), 1, data);
    dataVector.insert(dataVector.end(), 1, data);
    badSink(dataVector);

    delete data;
}


}
