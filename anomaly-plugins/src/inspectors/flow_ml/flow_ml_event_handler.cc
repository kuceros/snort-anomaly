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
// appid_listener_event_handler.cc author Shravan Rangaraju <shrarang@cisco.com>

#include "flow_ml_event_handler.h"

#include <iomanip>
#include <maxminddb.h>
#include <thread>
#include <string>
#include <bitset>

#include "flow/flow.h"
#include "network_inspectors/appid/appid_api.h"
#include "utils/stats.h"
#include "libml.h"

#include "detection/ips_context.h"
#include "utils/util.h"
#include "detection/detection_engine.h"
#include "log/log_text.h"

using namespace snort;
using namespace std;

std::vector<float> minMaxScaling(const std::vector<float>& data, const std::vector<float>& minVals, const std::vector<float>& maxVals) {
    std::vector<float> scaledData(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        scaledData[i] = (data[i] - minVals[i]) / (maxVals[i] - minVals[i]);
    }
    return scaledData;
}

ScalerInfo loadScalerInfo(const std::string& filename) {
    ScalerInfo scaler_info;

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file." << std::endl;
        return scaler_info;
    }

    uint32_t min_count;
    file.read(reinterpret_cast<char*>(&min_count), sizeof(min_count));

    std::vector<double> temp_min_values(min_count);
    file.read(reinterpret_cast<char*>(temp_min_values.data()), min_count * sizeof(double));

    scaler_info.min_values.resize(min_count);
    for (size_t i = 0; i < min_count; ++i) {
        scaler_info.min_values[i] = static_cast<float>(temp_min_values[i]);
    }

    uint32_t max_count;
    file.read(reinterpret_cast<char*>(&max_count), sizeof(max_count));

    std::vector<double> temp_max_values(max_count);
    file.read(reinterpret_cast<char*>(temp_max_values.data()), max_count * sizeof(double));

    scaler_info.max_values.resize(max_count);
    for (size_t i = 0; i < max_count; ++i) {
        scaler_info.max_values[i] = static_cast<float>(temp_max_values[i]);
    }

    file.close(); 

    return scaler_info;
}

std::string convertSecondsToDateTime(long seconds) {
    time_t timestamp = seconds;

    struct tm* timeinfo = localtime(&timestamp);

    char buffer[80];
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

    return std::string(buffer);
}


bool stringContains(const std::string& mainStr, const std::string& subStr) {
    return mainStr.find(subStr) != std::string::npos;
}

void FlowMLEventHandler::handle(DataEvent& event, Flow* flow)
{
    AppidEvent& appid_event = static_cast<AppidEvent&>(event);
    const AppidChangeBits& ac_bits = appid_event.get_change_bitset();

    const Packet *p = appid_event.get_packet();
    string src_name;
    string dst_name;

    int src_bytes = 0;
    int src_pkts = 0;
    int dst_bytes = 0;
    int dst_pkts = 0;

    AppidChangeBits temp_ac_bits = ac_bits;
    temp_ac_bits.reset(APPID_CREATED_BIT);
    temp_ac_bits.reset(APPID_DISCOVERY_FINISHED_BIT);
    if (temp_ac_bits.none())
        return;

    if (!flow)
    {
        WarningMessage("flow_ml: flow is null\n");
        return;
    }

    if (!appid_changed(ac_bits))
        return;

    char cli_ip_str[INET6_ADDRSTRLEN], srv_ip_str[INET6_ADDRSTRLEN];
    flow->client_ip.ntop(cli_ip_str, sizeof(cli_ip_str));
    flow->server_ip.ntop(srv_ip_str, sizeof(srv_ip_str));
    SfIp cli_ip = flow->client_ip;
    SfIp srv_ip = flow->server_ip;
    
    src_bytes = flow->flowstats.client_bytes;
    src_pkts = flow->flowstats.client_pkts;
    dst_bytes = flow->flowstats.server_bytes;
    dst_pkts = flow->flowstats.server_pkts;

    uint8_t proto = 0;

    if(p->is_ip())
        proto = flow->ip_proto;
    else if(p->is_tcp())
        proto = PROTO_TCP;
    else if(p->is_udp())
        proto = PROTO_UDP;
    else if(p->is_icmp())
        proto = PROTO_ICMP;

    ScalerInfo scaler_info = loadScalerInfo(config.scaler_file);

    std::vector<float> new_data = {(float)proto, (float)src_bytes, (float)src_pkts, (float)dst_bytes, (float)dst_pkts};

    std::vector<float> normalized_data = minMaxScaling(new_data, scaler_info.min_values, scaler_info.max_values);

    float output;
    if (!config.classifier.runFlowModel(normalized_data[0], normalized_data[1], normalized_data[2], normalized_data[3], normalized_data[4], output)) {
        std::cerr << "Failed to run inference." << std::endl;
        return;
    }

    float threshold = 0.9;
    
    if(config.threshold)
        threshold = (float)config.threshold;

    if(output > threshold)
        DetectionEngine::queue_event(FLOW_ML_GID, FLOW_ML_ATTACK);
}