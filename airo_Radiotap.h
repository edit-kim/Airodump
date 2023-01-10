#pragma once
#include <iostream>
#include <cstring>
#include <stdint.h>

struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* 2 */
        u_int8_t        it_pad;         /* 2 */
        u_int16_t       it_len;         /* entire length 4 */
        u_int32_t       it_present;     /* fields present */
        char            temp[10];
        u_int8_t        it_signal;      /**/
};
