#include "std_testcase.h"
#include "CWE401_Memory_Leak__new_twoIntsStruct_82.h"

namespace CWE401_Memory_Leak__new_twoIntsStruct_82
{


void bad()
{
    twoIntsStruct * data;
    data = NULL;

    data = new twoIntsStruct;

    data->intOne = 0;
    data->intTwo = 0;
    printStructLine(data);
    CWE401_Memory_Leak__new_twoIntsStruct_82_base* baseObject = new CWE401_Memory_Leak__new_twoIntsStruct_82_bad;
    baseObject->action(data);
    delete baseObject;
    delete data;
}


}
