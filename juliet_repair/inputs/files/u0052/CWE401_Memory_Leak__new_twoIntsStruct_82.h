#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__new_twoIntsStruct_82
{

class CWE401_Memory_Leak__new_twoIntsStruct_82_base
{
public:

    virtual void action(twoIntsStruct * data) = 0;
};


class CWE401_Memory_Leak__new_twoIntsStruct_82_bad : public CWE401_Memory_Leak__new_twoIntsStruct_82_base
{
public:
    void action(twoIntsStruct * data);
};


}
