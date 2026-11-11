#include "std_testcase.h"

#include <wchar.h>


void CWE401_Memory_Leak__int_realloc_01_bad()
{
    int * data;
    data = NULL;

    data = (int *)realloc(data, 100*sizeof(int));
    if (data == NULL) {exit(-1);}

    data[0] = 5;
    printIntLine(data[0]);

    ;
}
