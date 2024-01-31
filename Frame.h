#pragma once

#include <stdint.h>

struct RadiotapHeader {
    uint8_t verison;
    uint8_t pad;
    uint16_t length;
    uint32_t present;
};

struct BeaconFrame {
    uint16_t frame_ctl;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_control;

    uint64_t timestamp;         // timestamp. 8 bytes
    uint16_t beacon_interval;   // beacon interval. 2 byte
    uint16_t cap_info;          // capability information. 2 byte
    uint8_t* tag_param;
};

