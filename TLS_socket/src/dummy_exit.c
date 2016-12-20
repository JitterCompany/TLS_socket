#include "dummy_exit.h"

// used instead of exit(): exit() is not defined on all platforms.
void dummy_exit(int status)
{
    while(1);
}

