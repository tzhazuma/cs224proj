#include "std_testcase.h"

#include <wchar.h>


void CWE401_Memory_Leak__int64_t_malloc_01_bad()
{
    int64_t * data;
    data = NULL;

    data = (int64_t *)malloc(100*sizeof(int64_t));
    if (data == NULL) {exit(-1);}

    data[0] = 5LL;
    printLongLongLine(data[0]);

    ;
}
