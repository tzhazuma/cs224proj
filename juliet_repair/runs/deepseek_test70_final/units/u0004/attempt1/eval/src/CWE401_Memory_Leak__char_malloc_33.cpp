#include "std_testcase.h"

#include <wchar.h>

namespace CWE401_Memory_Leak__char_malloc_33
{


void bad()
{
    char * data;
    char * &dataRef = data;
    data = NULL;

    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}

    strcpy(data, "A String");
    printLine(data);
    {
        char * data = dataRef;

        ;
    }
    free(data);
}


}
