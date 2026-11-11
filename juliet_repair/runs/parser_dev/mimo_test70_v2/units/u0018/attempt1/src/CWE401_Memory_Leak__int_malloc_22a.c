#include "std_testcase.h"

#include <wchar.h>


int CWE401_Memory_Leak__int_malloc_22_badGlobal = 0;

void CWE401_Memory_Leak__int_malloc_22_badSink(int * data);

void CWE401_Memory_Leak__int_malloc_22_bad()
{
    int * data;
    data = NULL;

    data = (int *)malloc(100*sizeof(int));
    if (data == NULL) {exit(-1);}

    data[0] = 5;
    printIntLine(data[0]);
    CWE401_Memory_Leak__int_malloc_22_badGlobal = 1;
    CWE401_Memory_Leak__int_malloc_22_badSink(data);
    free(data);
}
