#include "std_testcase.h"
#include "CWE401_Memory_Leak__new_wchar_t_82.h"

namespace CWE401_Memory_Leak__new_wchar_t_82
{


void bad()
{
    wchar_t * data;
    data = NULL;

    data = new wchar_t;

    *data = L'A';
    printHexCharLine((char)*data);
    CWE401_Memory_Leak__new_wchar_t_82_base* baseObject = new CWE401_Memory_Leak__new_wchar_t_82_bad;
    baseObject->action(data);
    delete baseObject;
}


}
