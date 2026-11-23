#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *make_name(const char *who)
{
    char *name = (char *)malloc(strlen(who) + 8);
    if (name == NULL) exit(1);
    strcpy(name, "hello, ");
    strcat(name, who);
    return name;
}

int main(void)
{
    char *greeting = make_name("CS224");
    printf("%s\n", greeting);
    return 0;
}
