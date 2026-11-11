#include "std_testcase.h"
#include <vector>

#include <wchar.h>

using namespace std;

namespace CWE401_Memory_Leak__new_array_wchar_t_72
{


void badSink(vector<wchar_t *> dataVector);

void bad()
{
    wchar_t * data;
    vector<wchar_t *> dataVector;
    data = NULL;

    data = new wchar_t[100];

    wcscpy(data, L"A String");
    printWLine(data);

    dataVector.insert(dataVector.end(), 1, data);
    dataVector.insert(dataVector.end(), 1, data);
    dataVector.insert(dataVector.end(), 1, data);
    badSink(dataVector);

    delete [] data;
}


}
