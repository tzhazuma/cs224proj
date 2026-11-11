#include "std_testcase.h"

#include <wchar.h>


void CWE401_Memory_Leak__int_calloc_54b_badSink(int * data);

void CWE401_Memory_Leak__int_calloc_54_bad()
{
    int * data;
    data = NULL;

    data = (int *)calloc(100, sizeof(int));
    if (data == NULL) {exit(-1);}

    data[0] = 5;
    printIntLine(data[0]);
    CWE401_Memory_Leak__int_calloc_54b_badSink(data);
}
