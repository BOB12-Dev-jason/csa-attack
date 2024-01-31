#include <stdio.h>
#include <pcap.h>

#define ERROR_BEACON_CAPTURE -1

#include "Frame.h"

const unsigned char* capture_beacon(const char* interface);

int csa_attack(const char* interface, const char* ap_mac, const char* sta_mac) {


    // 1. ap_mac에 해당하는 beacon frame을 기다렸다가, 캡처한다.
    const unsigned char* captured_frame;
    captured_frame = capture_beacon(interface);
    if(captured_frame == ERROR_BEACON_CAPTURE) return -1;

    // 2. 캡처한 beacon frame의 정보를 변경한다.

    // 3. 변경한 beacon frame을 broadcast 혹은 unicast로 전송한다.


}


const unsigned char* capture_beacon(const char* interface) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    // pcap_t* handle = pcap_open_offline(ifname, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}

    struct pcap_pkthdr* header;
	const unsigned char* packet;

     while (1){
        int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
    }

}
