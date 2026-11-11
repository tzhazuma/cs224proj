#include "std_testcase.h"

#include <wchar.h>


void CWE401_Memory_Leak__char_realloc_54b_badSink(char * data);

void CWE401_Memory_Leak__char_realloc_54_bad()
{
    char * data;
    data = NULL;

    data = (char *)realloc(data, 100*sizeof(char));
    if (data == NULL) {exit(-1);}

    strcpy(data, "A String");
    printLine(data);
    CWE401_Memory_Leak__char_realloc_54b_badSink(data);
}
