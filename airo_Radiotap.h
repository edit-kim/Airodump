#pragma once
#include <iostream>
#include <cstring>
#include <stdint.h>

typedef struct RadiotapHeader {
        u_int8_t        it_version;     /* 2 */
        u_int16_t       it_len;         /* entire length 4 */
        u_int8_t        it_signal;      /**/
}RadiotapHeader;
