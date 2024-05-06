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
// interval_detector_event_handler.cc author Rostislav Kucera <kucera.rosta@gmail.com>, 2024
// based on appid_listener_event_handler.cc author Shravan Rangaraju <shrarang@cisco.com>

#ifndef INTERVAL_DETECTOR_EVENT_HANDLER_H
#define INTERVAL_DETECTOR_EVENT_HANDLER_H

#include <sstream>
#include <thread>
#include <maxminddb.h>

#include "framework/counts.h"
#include "framework/data_bus.h"
#include "helpers/json_stream.h"
#include "log/messages.h"
#include "network_inspectors/appid/application_ids.h"
#include "pub_sub/appid_events.h"
#include "interval_detector.h"

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

namespace snort
{
class AppIdSessionApi;
class Flow;
struct Packet;
}

typedef struct _group_stats
{
    uint64_t src_pkts = 0;
    uint64_t src_bytes = 0;
    uint64_t src_count = 0;
    uint64_t dst_count = 0;
    uint64_t dst_pkts = 0;
    uint64_t dst_bytes = 0;
    uint64_t udp_flows = 0;
    uint64_t tcp_flows = 0;
    uint64_t icmp_flows = 0;
    uint64_t time = 0;
    std::vector<uint64_t> src_pkts_per_inter;
    std::vector<uint64_t> src_bytes_per_inter;
    std::vector<uint64_t> dst_pkts_per_inter;
    std::vector<uint64_t> dst_bytes_per_inter;
    std::vector<uint64_t> dst_count_per_inter;
    std::vector<uint64_t> src_count_per_inter;
    std::vector<uint64_t> udp_flows_per_inter;
    std::vector<uint64_t> tcp_flows_per_inter;
    std::vector<uint64_t> icmp_flows_per_inter;
} GroupStats;

typedef struct _group_thresh
{
    double src_count_thresh = 0;
    double dst_count_thresh = 0;
    double src_pkt_thresh = 0;
    double src_bytes_thresh = 0;
    double dst_pkt_thresh = 0;
    double dst_bytes_thresh = 0;
    double udp_flows_thresh = 0;
    double tcp_flows_thresh = 0;
    double icmp_flows_thresh = 0;
} GroupThresholds;


typedef struct _flow_info {
    std::string src_ip;
    std::string dst_ip;
    uint8_t proto;
    std::vector<int> data;
} FlowInfo;

class IntervalDetectorEventHandler : public snort::DataHandler
{
public:
    IntervalDetectorEventHandler(IntervalDetectorConfig& config) :
        DataHandler(MOD_NAME), config(config) { }
    
    void handle(snort::DataEvent& event, snort::Flow* flow) override;

private:
    IntervalDetectorConfig& config;


    std::mutex stats_mutex;

    uint32_t window_start_time = 0;
    uint32_t interval_start_time = 0;
    uint32_t train_end_time = 0;

    std::map<std::string, GroupStats> stats_map;
    std::map<std::string, GroupThresholds> thresholds_map;

    std::vector<FlowInfo> interval_flows;
    std::vector<std::string> attack_src_ips;
    std::vector<std::string> attack_dst_ips;
    bool attack_udp = false;
    bool attack_tcp = false;
    bool attack_icmp = false;
    bool attack_others = false;

    int counter = 0;

    bool model_saved = false;
    bool interval_saved = false;

    bool appid_changed(const AppidChangeBits& ac_bits) const
    {
        if (ac_bits.test(APPID_RESET_BIT) or ac_bits.test(APPID_SERVICE_BIT) or
            ac_bits.test(APPID_CLIENT_BIT) or ac_bits.test(APPID_MISC_BIT) or
            ac_bits.test(APPID_PAYLOAD_BIT) or ac_bits.test(APPID_REFERRED_BIT))
            return true;

        return false;
    }

    std::vector<float> minMaxScaling(const std::vector<float>& data, const std::vector<float>& minVals, const std::vector<float>& maxVals);
    void saveModel(std::map<std::string, GroupThresholds>& thresholds_map, int interval, const std::string& filename);
    std::pair<std::map<std::string, GroupThresholds>, int> loadModel(const std::string& filename);
    float minMaxNormalize(int value, int max_val);
    void CalcUCL(int window, int interval, int num_sigma);
    std::string convertSecondsToDateTime(long seconds);
    bool stringContains(const std::string& mainStr, const std::string& subStr);
    bool checkGroupThresh(const std::map<std::string, GroupThresholds>& thresholds_map, const std::string& name, const GroupStats& stats);
    void queueEvent(std::string name, bool from, bool to);


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

    bool write_to_file(const std::string& str)
    {
        const std::lock_guard<std::mutex> lock(config.file_mutex);

        if (config.file_stream.is_open())
        {
            config.file_stream << str;
            return true;
        }

        return false;
    }

};

#endif
