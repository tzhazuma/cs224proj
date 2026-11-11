#include "std_testcase.h"
#include "CWE401_Memory_Leak__new_wchar_t_82.h"

namespace CWE401_Memory_Leak__new_wchar_t_82
{

void CWE401_Memory_Leak__new_wchar_t_82_bad::action(wchar_t * data)
{
    delete data;
}

}
