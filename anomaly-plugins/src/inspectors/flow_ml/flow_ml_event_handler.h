//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// flow_ml_event_handler.h author Rostislav Kucera <kucera.rosta@gmail.com>, 2024
// based on appid_listener_event_handler.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef FLOW_ML_EVENT_HANDLER_H
#define FLOW_ML_EVENT_HANDLER_H

#include <sstream>
#include <thread>

#include "framework/counts.h"
#include "framework/data_bus.h"
#include "helpers/json_stream.h"
#include "log/messages.h"
#include "network_inspectors/appid/application_ids.h"
#include "pub_sub/appid_events.h"
#include "flow_ml.h"

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

namespace snort
{
class AppIdSessionApi;
class Flow;
struct Packet;
}

struct ScalerInfo {
    std::vector<float> min_values;
    std::vector<float> max_values;
};

class FlowMLEventHandler : public snort::DataHandler
{
public:
    FlowMLEventHandler(FlowMLConfig& config) :
        DataHandler(MOD_NAME), config(config) { }

    void handle(snort::DataEvent& event, snort::Flow* flow) override;

private:
    FlowMLConfig& config;


    bool appid_changed(const AppidChangeBits& ac_bits) const
    {
        if (ac_bits.test(APPID_RESET_BIT) or ac_bits.test(APPID_SERVICE_BIT) or
            ac_bits.test(APPID_CLIENT_BIT) or ac_bits.test(APPID_MISC_BIT) or
            ac_bits.test(APPID_PAYLOAD_BIT) or ac_bits.test(APPID_REFERRED_BIT))
            return true;

        return false;
    }

    std::string get_proto_str(uint8_t ip_proto) const
    {
        switch(ip_proto)
        {
        case 1:
            return "ICMP";
        case 2:
            return "IGMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        default:
            return std::to_string(ip_proto);
        }
    }

};

#endif
