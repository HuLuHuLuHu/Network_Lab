#include "arp.h"
#include <stdio.h>

int main(int argc, char const *argv[])
{
    printf("%ld\n", sizeof(struct ether_arp));
    return 0;
}