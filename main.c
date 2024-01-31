#include <stdio.h>
#include <string.h>

#include "deauth-attack.h"

void usage();

int main(int argc, char* argv[]) {

    const char* interface;
    const char* ap_mac;
    const char* station_mac;

    int res;

    switch (argc) {
    case 3:
        puts("case 3");
        break;
    
    default:
        usage();
        res = -1;
        break;
    }

    

    return res;
    
}

void usage() {
    puts("syntax: csa-attack <interfrace> <ap mac> [<station mac>]");
    puts("sample: csa-attack wlan0 aa:bb:cc:dd:ee:ff 11:22:33:44:55:66");
}
