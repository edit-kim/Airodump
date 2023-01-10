#pragma once
#include <iostream>
#include <cstring>
#include <stdint.h>

typedef struct RadiotapHeader {
        u_int8_t        it_version;
        u_int16_t       it_len;         
        int8_t        it_signal;      
}RadiotapHeader;
