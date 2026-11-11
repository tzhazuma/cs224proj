#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_wchar_t_82
{

class CWE401_Memory_Leak__new_wchar_t_82_base
{
public:

    virtual void action(wchar_t * data) = 0;
    virtual ~CWE401_Memory_Leak__new_wchar_t_82_base() {}
};


class CWE401_Memory_Leak__new_wchar_t_82_bad : public CWE401_Memory_Leak__new_wchar_t_82_base
{
public:
    void action(wchar_t * data);
};


}
