#include "pch.h"
#include "helper.h"
#include <system_error>

int char2int(char input)
{
    if (input >= '0' && input <= '9')
    {
        return input - '0';
    }

    if (input >= 'A' && input <= 'F')
    {
        return input - 'A' + 10;
    }

    if (input >= 'a' && input <= 'f')
    {
        return input - 'a' + 10;
    }

    throw std::invalid_argument("Invalid input string");
}

void hex2bin(const char *src, char *target)
{
    while (*src && src[1])
    {
        *target = (char2int(*src) * 16) + char2int(src[1]);
        target++;
        src += 2;
    }
}
