#include "std_testcase.h"
#include <vector>

#include <wchar.h>

using namespace std;

namespace CWE401_Memory_Leak__new_char_72
{


void badSink(vector<char *> dataVector);

void bad()
{
    char * data;
    vector<char *> dataVector;
    data = NULL;

    data = new char;

    *data = 'A';
    printHexCharLine(*data);

    dataVector.insert(dataVector.end(), 1, data);
    dataVector.insert(dataVector.end(), 1, data);
    dataVector.insert(dataVector.end(), 1, data);
    badSink(dataVector);

    delete data;
}


}
