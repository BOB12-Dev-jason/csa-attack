#pragma once

#include <stdint.h>

#pragma pack(push, 1)
struct RadiotapHeader {
    uint8_t verison;
    uint8_t pad;
    uint16_t length;
    uint32_t present;
};


struct Dot11FrameHeader {
    uint16_t frame_ctl;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_control;
};


struct BeaconFrameBody {
    uint64_t timestamp;         // timestamp. 8 bytes
    uint16_t beacon_interval;   // beacon interval. 2 byte
    uint16_t cap_info;          // capability information. 2 byte
};


struct BeaconFrame {
    struct Dot11FrameHeader f_hdr;
    struct BeaconFrameBody body;
};


struct Tag_param {
    uint8_t tag_num;
    uint8_t tag_len;
};
#pragma pack(pop)

