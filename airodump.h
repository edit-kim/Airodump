#pragma once

#include <iostream>
#include <cstring>
#include "airo_Beacon.h"
#include "airo_Radiotap.h"
#include "airo_WirelessManagement.h"

typedef struct AirodumpData {
    RadiotapHeader radiotapHeader;
    BeaconFrame beaconFrame;
    WirelessManagement wirelessManagement;
    int beacon = 0;
}AirodumpData;