#include <stdio.h>
#include <string.h>

#include "csa-attack.h"

void usage();

int main(int argc, char* argv[]) {

    const char* interface;
    const char* ap_mac;
    const char* station_mac;

    int res;

    switch (argc) {
        case 3: // csa-attack <interface> <ap mac>
            interface = argv[1];
            ap_mac = argv[2];
            if (strlen(ap_mac) != 17) {
                usage();
                return -1;
            }
            res = csa_attack(interface, ap_mac, NULL);
            break;

        case 4: // csa-attack <interface> <ap mac> <station mac>
            interface = argv[1];
            ap_mac = argv[2];
            station_mac = argv[3];
            if ((strlen(ap_mac) != 17) || (strlen(station_mac) != 17)) {
                usage();
                return -1;
            }
            res = csa_attack(interface, ap_mac, station_mac);
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
