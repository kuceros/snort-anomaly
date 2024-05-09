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

#include "interval_detector_event_handler.h"

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
#include "log/log.h"

using namespace snort;
using namespace std;

/**
 * @brief Saves the given thresholds map to a file.
 * 
 * @param thresholds_map The thresholds map to be saved.
 * @param interval The interval for which the thresholds were calculated.
 * @param filename The name of the file to which the thresholds map will be saved.
 */
void IntervalDetectorEventHandler::saveModel(map<string, GroupThresholds>& thresholds_map, int interval, const string& filename) {
    ofstream outfile(filename, ios::binary);
    if (!outfile.is_open()) {
        WarningMessage("Error opening file: %s\n",filename.c_str());
        return;
    }

    outfile.write(reinterpret_cast<const char*>(&interval), sizeof(int));
    size_t map_size = thresholds_map.size();
    outfile.write(reinterpret_cast<const char*>(&map_size), sizeof(size_t));

    for (const auto& pair : thresholds_map) {
        size_t key_size = pair.first.size();
        outfile.write(reinterpret_cast<const char*>(&key_size), sizeof(size_t));
        outfile.write(pair.first.data(), key_size);

        outfile.write(reinterpret_cast<const char*>(&pair.second), sizeof(GroupThresholds));
    }
    thresholds_map.clear();
    outfile.close();
}

/**
 * @brief Loads a thresholds map from a file.
 * 
 * This function reads the interval and the size of the thresholds map from the file first. Then, for each pair in the thresholds map, it reads the size of the key, the key itself, and the value from the file. It throws a runtime error if the file cannot be opened.
 * 
 * @param filename The name of the file from which the thresholds map will be loaded.
 * @return pair<map<string, GroupThresholds>, int> The loaded thresholds map and the interval.
 */
pair<map<string, GroupThresholds>, int> IntervalDetectorEventHandler::loadModel(const string& filename) {
    map<string, GroupThresholds> thresholds_map;
    int interval = 0;

    ifstream infile(filename, ios::binary);
    if (!infile.is_open()) {
        throw runtime_error("Error opening file: " + filename);
    }

    infile.read(reinterpret_cast<char*>(&interval), sizeof(int));

    size_t map_size;
    infile.read(reinterpret_cast<char*>(&map_size), sizeof(size_t));

    double sum_src_pkt_thresh = 0.0;
    double sum_src_bytes_thresh = 0.0;
    double sum_dst_pkt_thresh = 0.0;
    double sum_dst_bytes_thresh = 0.0;
    double sum_dst_count_thresh = 0.0;
    double sum_src_count_thresh = 0.0;
    double sum_udp_flows_thresh = 0.0;
    double sum_tcp_flows_thresh = 0.0;
    double sum_icmp_flows_thresh = 0.0;

    int count_src_pkt_thresh = 0;
    int count_src_bytes_thresh = 0;
    int count_dst_pkt_thresh = 0;
    int count_dst_bytes_thresh = 0;
    int count_dst_count_thresh = 0;
    int count_src_count_thresh = 0;
    int count_udp_flows_thresh = 0;
    int count_tcp_flows_thresh = 0;
    int count_icmp_flows_thresh = 0;


    for (size_t i = 0; i < map_size; ++i) {
        size_t key_size;
        infile.read(reinterpret_cast<char*>(&key_size), sizeof(size_t));
        if (infile.fail()) {
            throw runtime_error("Error reading key size from file: " + filename);
        }

        string key;
        key.resize(key_size);
        infile.read(&key[0], key_size);
        if (infile.fail()) {
            throw runtime_error("Error reading key from file: " + filename);
        }

        GroupThresholds value;
        infile.read(reinterpret_cast<char*>(&value), sizeof(GroupThresholds));
        if (infile.fail()) {
            throw runtime_error("Error reading GroupThresholds from file: " + filename);
        }
        thresholds_map[key] = value;
        sum_src_pkt_thresh += value.src_pkt_thresh;
        sum_src_bytes_thresh += value.src_bytes_thresh;
        sum_dst_pkt_thresh += value.dst_pkt_thresh;
        sum_dst_bytes_thresh += value.dst_bytes_thresh;
        sum_dst_count_thresh += value.dst_count_thresh;
        sum_src_count_thresh += value.src_count_thresh;
        sum_udp_flows_thresh += value.udp_flows_thresh;
        sum_tcp_flows_thresh += value.tcp_flows_thresh;
        sum_icmp_flows_thresh += value.icmp_flows_thresh;

        if(value.src_pkt_thresh != 0)
            count_src_pkt_thresh++;
        if(value.src_bytes_thresh != 0)
            count_src_bytes_thresh++;
        if(value.dst_pkt_thresh != 0)
            count_dst_pkt_thresh++;
        if(value.dst_bytes_thresh != 0)
            count_dst_bytes_thresh++;
        if(value.dst_count_thresh != 0)
            count_dst_count_thresh++;
        if(value.src_count_thresh != 0)
            count_src_count_thresh++;
        if(value.udp_flows_thresh != 0)
            count_udp_flows_thresh++;
        if(value.tcp_flows_thresh != 0)
            count_tcp_flows_thresh++;
        if(value.icmp_flows_thresh != 0)
            count_icmp_flows_thresh++;
        
    }

    GroupThresholds def_value;
    def_value.src_pkt_thresh = sum_src_pkt_thresh/count_src_pkt_thresh;
    def_value.src_bytes_thresh = sum_src_bytes_thresh/count_src_bytes_thresh;
    def_value.dst_pkt_thresh = sum_dst_pkt_thresh/count_dst_pkt_thresh;
    def_value.dst_bytes_thresh = sum_dst_bytes_thresh/count_dst_bytes_thresh;
    def_value.dst_count_thresh = sum_dst_count_thresh/count_dst_count_thresh;
    def_value.src_count_thresh = sum_src_count_thresh/count_src_count_thresh;
    def_value.udp_flows_thresh = sum_udp_flows_thresh/count_udp_flows_thresh;
    def_value.tcp_flows_thresh = sum_tcp_flows_thresh/count_tcp_flows_thresh;   
    def_value.icmp_flows_thresh = sum_icmp_flows_thresh/count_icmp_flows_thresh;
    thresholds_map["def"] = def_value;

    infile.close();

    return {thresholds_map, interval};
}

/**
 * @brief Calculates the Upper Control Limit (UCL) for the given parameters.
 * 
 * This function iterates over the stats_map and calculates the sum of source count, destination count, and source bytes. The details of the calculation are not provided in the code snippet.
 * 
 * @param window The window size for the UCL calculation.
 * @param interval The interval for the UCL calculation.
 * @param num_sigma The number of standard deviations for the UCL calculation.
 */
void IntervalDetectorEventHandler::CalcUCL(int window, int interval, int num_sigma){

    for (auto& it : stats_map)
    {
        uint64_t sum_src_count = 0;
        uint64_t sum_dst_count = 0;
        uint64_t sum_src_bytes = 0;
        uint64_t sum_src_packets = 0;
        uint64_t sum_dst_bytes = 0;
        uint64_t sum_dst_packets = 0;
        uint64_t sum_udp_flows = 0;
        uint64_t sum_tcp_flows = 0;
        uint64_t sum_icmp_flows = 0;
        double avg_src_bytes = 0.0;
        double avg_src_packets = 0.0;
        double avg_dst_bytes = 0.0;
        double avg_dst_packets = 0.0;
        double avg_dst_count = 0.0;
        double avg_src_count = 0.0;
        double avg_udp_flows = 0.0;
        double avg_tcp_flows = 0.0;
        double avg_icmp_flows = 0.0;

        int counter = 0;

        string name = it.first;
        GroupStats stats = it.second;

        stats_map[name].src_pkts_per_inter.push_back(stats_map[name].src_pkts);
        stats_map[name].src_bytes_per_inter.push_back(stats_map[name].src_bytes);
        stats_map[name].dst_pkts_per_inter.push_back(stats_map[name].dst_pkts);
        stats_map[name].dst_bytes_per_inter.push_back(stats_map[name].dst_bytes);
        stats_map[name].dst_count_per_inter.push_back(stats_map[name].dst_count);
        stats_map[name].src_count_per_inter.push_back(stats_map[name].src_count);
        stats_map[name].udp_flows_per_inter.push_back(stats_map[name].udp_flows);
        stats_map[name].tcp_flows_per_inter.push_back(stats_map[name].tcp_flows);
        stats_map[name].icmp_flows_per_inter.push_back(stats_map[name].icmp_flows);

        stats_map[name].src_pkts = 0;
        stats_map[name].src_bytes = 0;
        stats_map[name].dst_pkts = 0;
        stats_map[name].dst_bytes = 0;
        stats_map[name].dst_count = 0;
        stats_map[name].src_count = 0;
        stats_map[name].udp_flows = 0;
        stats_map[name].tcp_flows = 0;
        stats_map[name].icmp_flows = 0;


        for (auto& iter : stats.src_bytes_per_inter)
        {
            counter++;
            sum_src_bytes += iter;
        }

        for (auto& iter : stats.src_pkts_per_inter)
        {
            sum_src_packets += iter;
        }

        for (auto& iter : stats.dst_bytes_per_inter)
        {
            sum_dst_bytes += iter;
        }

        for (auto& iter : stats.dst_pkts_per_inter)
        {
            sum_dst_packets += iter;
        }

        for (auto& iter : stats.dst_count_per_inter)
        {
            sum_dst_count += iter;
        }

        for (auto& iter : stats.src_count_per_inter)
        {
            sum_src_count += iter;
        }

        for (auto& iter : stats.udp_flows_per_inter)
        {
            sum_udp_flows += iter;
        }

        for (auto& iter : stats.tcp_flows_per_inter)
        {
            sum_tcp_flows += iter;
        }

        for (auto& iter : stats.icmp_flows_per_inter)
        {
            sum_icmp_flows += iter;
        }


        if(counter == 0)
        {
            continue;
        }
        
        avg_src_bytes = sum_src_bytes / (counter); 
        avg_src_packets = sum_src_packets / counter;
        avg_dst_bytes = sum_dst_bytes / counter;
        avg_dst_packets = sum_dst_packets / counter;
        avg_dst_count = sum_dst_count / counter;
        avg_src_count = sum_src_count /counter;
        avg_udp_flows = sum_udp_flows / counter;
        avg_tcp_flows = sum_tcp_flows / counter;
        avg_icmp_flows = sum_icmp_flows / counter;

        double dev_src_bytes = 0.0;
        double dev_src_packets = 0.0;
        double dev_dst_bytes = 0.0;
        double dev_dst_packets = 0.0;
        double dev_dst_count = 0.0;
        double dev_src_count = 0.0;
        double dev_udp_flows = 0.0;
        double dev_tcp_flows = 0.0;
        double dev_icmp_flows = 0.0;

        for (auto& iter : stats.src_bytes_per_inter)
        {
            dev_src_bytes += (iter - avg_src_bytes) * (iter - avg_src_bytes);
        
        }

        for (auto& iter : stats.dst_bytes_per_inter)
        {
            dev_dst_bytes += (iter - avg_dst_bytes) * (iter - avg_dst_bytes);
        
        }

        for (auto& iter : stats.src_pkts_per_inter)
        {
            dev_src_packets += (iter - avg_src_packets) * (iter - avg_src_packets);
        
        }

        for (auto& iter : stats.dst_pkts_per_inter)
        {
            dev_dst_packets += (iter - avg_dst_packets) * (iter - avg_dst_packets);
        
        }

        for (auto& iter : stats.dst_count_per_inter)
        {
            dev_dst_count += (iter - avg_dst_count) * (iter - avg_dst_count);
        
        }

        for (auto& iter : stats.src_count_per_inter)
        {
            dev_src_count += (iter - avg_src_count) * (iter - avg_src_count);
        
        }

        for (auto& iter : stats.udp_flows_per_inter)
        {
            dev_udp_flows += (iter - avg_udp_flows) * (iter - avg_udp_flows);
        
        }

        for (auto& iter : stats.tcp_flows_per_inter)
        {
            dev_tcp_flows += (iter - avg_tcp_flows) * (iter - avg_tcp_flows);
        
        }

        for (auto& iter : stats.icmp_flows_per_inter)
        {
            dev_icmp_flows += (iter - avg_icmp_flows) * (iter - avg_icmp_flows);
        
        }

        double varc_src_bytes = dev_src_bytes/counter;
        double std_dev_src_bytes = sqrt(varc_src_bytes); 
        double varc_src_packets = dev_src_packets/counter;
        double std_dev_src_packets = sqrt(varc_src_packets);
        double varc_dst_bytes = dev_dst_bytes/counter; 
        double std_dev_dst_bytes = sqrt(varc_dst_bytes);
        double varc_dst_packets = dev_dst_packets/counter;
        double std_dev_dst_packets = sqrt(varc_dst_packets);
        double varc_dst_count = dev_dst_count/counter;
        double std_dev_dst_count = sqrt(varc_dst_count);
        double varc_src_count = dev_src_count/counter;
        double std_dev_src_count = sqrt(varc_src_count);
        double varc_udp_flows = dev_udp_flows/counter;
        double std_dev_udp_flows = sqrt(varc_udp_flows);
        double varc_tcp_flows = dev_tcp_flows/counter;
        double std_dev_tcp_flows = sqrt(varc_tcp_flows);
        double varc_icmp_flows = dev_icmp_flows/counter;
        double std_dev_icmp_flows = sqrt(varc_icmp_flows);

        thresholds_map[name].src_pkt_thresh = avg_src_packets + (num_sigma * std_dev_src_packets);
        thresholds_map[name].src_bytes_thresh = avg_src_bytes + (num_sigma * std_dev_src_bytes);
        thresholds_map[name].dst_pkt_thresh = avg_dst_packets + (num_sigma * std_dev_dst_packets);
        thresholds_map[name].dst_bytes_thresh = avg_dst_bytes + (num_sigma * std_dev_dst_bytes);
        thresholds_map[name].dst_count_thresh = avg_dst_count + (num_sigma * std_dev_dst_count);
        thresholds_map[name].src_count_thresh = avg_src_count + (num_sigma * std_dev_src_count);
        thresholds_map[name].udp_flows_thresh = avg_udp_flows + (num_sigma * std_dev_udp_flows);
        thresholds_map[name].tcp_flows_thresh = avg_tcp_flows + (num_sigma * std_dev_tcp_flows);
        thresholds_map[name].icmp_flows_thresh = avg_icmp_flows + (num_sigma * std_dev_icmp_flows);
    }

    stats_map.clear();
    return;
}

/**
 * @brief Converts seconds to a datetime string.
 * 
 * This function converts the given seconds to a time_t, converts that to a tm struct using localtime, and then formats that into a string using strftime.
 * 
 * @param seconds The seconds to be converted.
 * @return string The datetime string.
 */
string IntervalDetectorEventHandler::convertSecondsToDateTime(long seconds) {
    time_t timestamp = seconds;

    struct tm* timeinfo = localtime(&timestamp);

    char buffer[80];
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

    return string(buffer);
}

/**
 * @brief Queues an event based on the given parameters and the thresholds map.
 * 
 * This function checks if the given name exists in the stats_map and the thresholds_map. If the name exists and the from parameter is true and the to parameter is false, it checks if the udp_flows, tcp_flows, or icmp_flows for the name in the stats_map exceed their respective thresholds in the thresholds_map. If any of the flows exceed their threshold, it queues the corresponding event.
 * 
 * @param name The name of the group to check.
 * @param from The from flag for the event.
 * @param to The to flag for the event.
 */
void IntervalDetectorEventHandler::queueEvent(string name, bool from, bool to) {
    if(from and !to)
    {
        if(stats_map[name].udp_flows > thresholds_map[name].udp_flows_thresh)
        {
            DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_FROM_UDP);
            attack_udp = true;
        }
        else if(stats_map[name].tcp_flows > thresholds_map[name].tcp_flows_thresh)
        {
            DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_FROM_TCP);
            attack_tcp = true;
        }
        else if(stats_map[name].icmp_flows > thresholds_map[name].icmp_flows_thresh)
        {
            DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_FROM_ICMP);
            attack_icmp = true;
        }
        else
        {
            DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_FROM_OTHERS);
            attack_others = true;
        }
    }
    else if(!from and to)
    {
        if(stats_map[name].udp_flows > thresholds_map[name].udp_flows_thresh)
        {
            DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_TO_UDP);
            attack_udp = true;
        }
        else if(stats_map[name].tcp_flows > thresholds_map[name].tcp_flows_thresh)
        {
            DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_TO_TCP);
            attack_tcp = true;
        }
        else if(stats_map[name].icmp_flows > thresholds_map[name].icmp_flows_thresh)
        {
            DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_TO_ICMP);
            attack_icmp = true;
        }
        else
        {
            DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_TO_OTHERS);
            attack_others = true;
        }
    }
}

/**
 * Handles the given data event for the specified flow.
 * 
 * This function is detecting DoS(DDoS) attacks based on the number of packets, bytes and number of flows in a given interval.
 * 
 * @param event - The data event to handle.
 * @param flow - The flow for which to handle the event.
 */
void IntervalDetectorEventHandler::handle(DataEvent& event, Flow* flow)
{
    AppidEvent& appid_event = static_cast<AppidEvent&>(event);

    const Packet *p = appid_event.get_packet();
    string src_name;
    string dst_name;

    int src_bytes = 0;
    int src_pkts = 0;
    int dst_bytes = 0;
    int dst_pkts = 0;

    if (!flow)
    {
        WarningMessage("interval_detector: flow is null\n");
        return;
    }

    uint8_t proto = 0;

    if(p->is_ip())
        proto = flow->ip_proto;
    else if(p->is_tcp())
        proto = PROTO_TCP;
    else if(p->is_udp())
        proto = PROTO_UDP;
    else if(p->is_icmp())
        proto = PROTO_ICMP;

    char cli_ip_str[INET6_ADDRSTRLEN], srv_ip_str[INET6_ADDRSTRLEN];
    flow->client_ip.ntop(cli_ip_str, sizeof(cli_ip_str));
    flow->server_ip.ntop(srv_ip_str, sizeof(srv_ip_str));
    SfIp cli_ip = flow->client_ip;
    SfIp srv_ip = flow->server_ip;

    MMDB_s my_mmdb;
    int status = MMDB_open(config.db_name.c_str(), MMDB_MODE_MMAP, &my_mmdb);
    if (status != MMDB_SUCCESS and strcmp(config.db_name.c_str(), "") != 0){
        WarningMessage("%s\n", MMDB_strerror(status));
    }
    uint32_t asn_client = 0;
    uint32_t asn_server = 0;
    uint32_t asn = 0;
    MMDB_lookup_result_s result_client;
    MMDB_lookup_result_s result_server;
    int error;
    int db_error;

    result_client = MMDB_lookup_string(&my_mmdb, cli_ip_str, &error, &db_error);
    result_server = MMDB_lookup_string(&my_mmdb, srv_ip_str, &error, &db_error);

    MMDB_entry_data_s entry_data;
    if (result_client.found_entry && MMDB_get_value(&result_client.entry, &entry_data, "autonomous_system_number", NULL) == MMDB_SUCCESS) {
        if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UINT32) {
            asn_client = entry_data.uint32;
        }
    }
    if (result_server.found_entry && MMDB_get_value(&result_server.entry, &entry_data, "autonomous_system_number", NULL) == MMDB_SUCCESS) {
        if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UINT32) {
            asn_server = entry_data.uint32;
        }
    }

    if (status == MMDB_SUCCESS)
        MMDB_close(&my_mmdb);

    stats_mutex.lock();
    if(config.training)
    {
        
        if(train_end_time == 0)
        {
            train_end_time = p->pkth->ts.tv_sec + config.window;
        }

        if(p->pkth->ts.tv_sec > train_end_time and !model_saved)
        {
            CalcUCL(config.window, config.interval, config.num_sigma);
            saveModel(thresholds_map, config.interval, config.model);
            model_saved = true;
            stats_mutex.unlock();
            return;
        }
        
    }
    stats_mutex.unlock();
    stats_mutex.lock();
    if(window_start_time == 0)
    {
        if(config.load_model and !config.training)
        {
            try
            {
                tie(thresholds_map, config.interval)= loadModel(config.model);
            }
            catch(const exception& e)
            {
                WarningMessage("%s\n",e.what());
            }
        }
        window_start_time = p->pkth->ts.tv_sec;
        interval_start_time = window_start_time;
        DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_INTERVAL);
    }
    else if(window_start_time+config.window < p->pkth->ts.tv_sec)
    {
        window_start_time += config.window;
        interval_start_time = window_start_time;
        if(!config.load_model and !config.training)
        {
            CalcUCL(config.window, config.interval, config.num_sigma);
        }
        stats_map.clear();

        DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_INTERVAL);    
    }
    stats_mutex.unlock();

    stats_mutex.lock();
    if(interval_start_time+config.interval < p->pkth->ts.tv_sec)
    {
        for (auto& it : stats_map)
        {
            string name = it.first;
            GroupStats stats = it.second;
            GroupThresholds threshold = thresholds_map[name];

            if(!config.load_model)
            {
                stats_map[name].src_pkts_per_inter.push_back(stats_map[name].src_pkts);
                stats_map[name].src_bytes_per_inter.push_back(stats_map[name].src_bytes);
                stats_map[name].dst_pkts_per_inter.push_back(stats_map[name].dst_pkts);
                stats_map[name].dst_bytes_per_inter.push_back(stats_map[name].dst_bytes);
                stats_map[name].dst_count_per_inter.push_back(stats_map[name].dst_count);
                stats_map[name].src_count_per_inter.push_back(stats_map[name].src_count);
                stats_map[name].udp_flows_per_inter.push_back(stats_map[name].udp_flows);
                stats_map[name].tcp_flows_per_inter.push_back(stats_map[name].tcp_flows);
                stats_map[name].icmp_flows_per_inter.push_back(stats_map[name].icmp_flows);
            }

            stats_map[name].src_pkts = 0;
            stats_map[name].src_bytes = 0;
            stats_map[name].dst_pkts = 0;
            stats_map[name].dst_bytes = 0;
            stats_map[name].dst_count = 0;
            stats_map[name].src_count = 0;
            stats_map[name].udp_flows = 0;
            stats_map[name].tcp_flows = 0;
            stats_map[name].icmp_flows = 0;
        }
        
        DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_INTERVAL); 

        for (auto it = interval_flows.begin(); it != interval_flows.end(); ) 
        {
            if (find(attack_src_ips.begin(), attack_src_ips.end(), it->src_ip) != attack_src_ips.end()) {
                if(it->proto == PROTO_UDP and attack_udp)
                {
                    ostringstream ss;
                    ss << static_cast<unsigned>(it->proto) << ", " << it->data[0] << ", " << it->data[1] << ", " << it->data[2] << ", " << it->data[3] << ", 1"<< endl;
                    if (!write_to_file(ss.str())) {
                        LogMessage("%s", ss.str().c_str());
                    }
                    it = interval_flows.erase(it);
                }
                else if(it->proto == PROTO_TCP and attack_tcp)
                {
                    ostringstream ss;
                    ss << static_cast<unsigned>(it->proto) << ", " << it->data[0] << ", " << it->data[1] << ", " << it->data[2] << ", " << it->data[3] << ", 1"<< endl;
                    if (!write_to_file(ss.str())) {
                        LogMessage("%s", ss.str().c_str());
                    }
                    it = interval_flows.erase(it);
                }
                else if(it->proto == PROTO_ICMP and attack_icmp)
                {
                    ostringstream ss;
                    ss << static_cast<unsigned>(it->proto) << ", " << it->data[0] << ", " << it->data[1] << ", " << it->data[2] << ", " << it->data[3] << ", 1"<< endl;
                    if (!write_to_file(ss.str())) {
                        LogMessage("%s", ss.str().c_str());
                    }
                    it = interval_flows.erase(it);
                }
                else if(attack_others and it->proto != PROTO_UDP and it->proto != PROTO_TCP and it->proto != PROTO_ICMP)
                {
                    ostringstream ss;
                    ss << static_cast<unsigned>(it->proto) << ", " << it->data[0] << ", " << it->data[1] << ", " << it->data[2] << ", " << it->data[3] << ", 1"<< endl;
                    if (!write_to_file(ss.str())) {
                        LogMessage("%s", ss.str().c_str());
                    }
                    it = interval_flows.erase(it);
                }
                else
                {
                    ostringstream ss;
                    ss << static_cast<unsigned>(it->proto) << ", " << it->data[0] << ", " << it->data[1] << ", " << it->data[2] << ", " << it->data[3] << ", 0"<< endl;
                    if (!write_to_file(ss.str())) {
                        LogMessage("%s", ss.str().c_str());
                    }
                    it = interval_flows.erase(it);
                
                }
            }
            else if (find(attack_dst_ips.begin(), attack_dst_ips.end(), it->dst_ip) != attack_dst_ips.end()) {
             
                if(it->proto == PROTO_UDP and attack_udp)
                {
                    ostringstream ss;
                    ss << static_cast<unsigned>(it->proto) << ", " << it->data[0] << ", " << it->data[1] << ", " << it->data[2] << ", " << it->data[3] << ", 1"<< endl;
                    if (!write_to_file(ss.str())) {
                        LogMessage("%s", ss.str().c_str());
                    }
                    it = interval_flows.erase(it);
                }
                else if(it->proto == PROTO_TCP and attack_tcp and it->tcp_syn)
                {
                    ostringstream ss;
                    ss << static_cast<unsigned>(it->proto) << ", " << it->data[0] << ", " << it->data[1] << ", " << it->data[2] << ", " << it->data[3] << ", 1"<< endl;
                    if (!write_to_file(ss.str())) {
                        LogMessage("%s", ss.str().c_str());
                    }
                    it = interval_flows.erase(it);
                }
                else if(it->proto == PROTO_ICMP and attack_icmp)
                {
                    ostringstream ss;
                    ss << static_cast<unsigned>(it->proto) << ", " << it->data[0] << ", " << it->data[1] << ", " << it->data[2] << ", " << it->data[3] << ", 1"<< endl;
                    if (!write_to_file(ss.str())) {
                        LogMessage("%s", ss.str().c_str());
                    }
                    it = interval_flows.erase(it);
                }
                else if(attack_others)
                {
                    ostringstream ss;
                    ss << static_cast<unsigned>(it->proto) << ", " << it->data[0] << ", " << it->data[1] << ", " << it->data[2] << ", " << it->data[3] << ", 1"<< endl;
                    if (!write_to_file(ss.str())) {
                        LogMessage("%s", ss.str().c_str());
                    }
                    it = interval_flows.erase(it);
                }
                else
                {
                    ostringstream ss;
                    ss << static_cast<unsigned>(it->proto) << ", " << it->data[0] << ", " << it->data[1] << ", " << it->data[2] << ", " << it->data[3] << ", 0"<< endl;
                    if (!write_to_file(ss.str())) {
                        LogMessage("%s", ss.str().c_str());
                    }
                    it = interval_flows.erase(it);
                }

            } else {
                ostringstream ss;
                ss << static_cast<unsigned>(it->proto) << ", " << it->data[0] << ", " << it->data[1] << ", " << it->data[2] << ", " << it->data[3] << ", 0"<< endl;
                if (!write_to_file(ss.str())) {
                    LogMessage("%s", ss.str().c_str());
                }
                it = interval_flows.erase(it);
            }
        }

        attack_dst_ips.clear();
        attack_src_ips.clear();
        interval_flows.clear();
        attack_udp = false;
        attack_tcp = false;
        attack_icmp = false;
        attack_others = false;
    
        interval_start_time +=config.interval;
    }
    stats_mutex.unlock();

    bool found = false;
    for (auto& it : config.default_ips)
    {
        string name = it.first;
        vector<const snort::SfCidr*> ip_addresses = it.second;
        for (auto& ip : ip_addresses)
        {
            int comp = ip->contains(&cli_ip); 
             
            if(comp == SFIP_CONTAINS and name!="EXTERNAL_NET")
            {
                stats_mutex.lock();
                if(interval_start_time == 0)
                {
                    interval_start_time = window_start_time;
                }  
                stats_mutex.unlock();
                stats_map[name].src_pkts += flow->flowstats.client_pkts;
                stats_map[name].src_bytes += flow->flowstats.client_bytes;
                stats_map[name].src_count++;
                if(proto == PROTO_UDP)
                {
                    stats_map[name].udp_flows++;
                }
                else if(proto == PROTO_TCP)
                {
                    stats_map[name].tcp_flows++;
                }
                else if(proto == PROTO_ICMP)
                {
                    stats_map[name].icmp_flows++;
                }

                src_bytes = flow->flowstats.client_bytes;
                src_pkts = flow->flowstats.client_pkts;
                src_name = name;

                GroupThresholds threshold = thresholds_map[name];

                if(threshold.src_bytes_thresh>0 and threshold.src_pkt_thresh>0 and threshold.src_count_thresh>0)
                {
                    if(stats_map[name].src_pkts > threshold.src_pkt_thresh or stats_map[name].src_bytes > threshold.src_bytes_thresh or stats_map[name].src_count > threshold.src_count_thresh)
                    {
                        auto it = find(attack_src_ips.begin(), attack_src_ips.end(), name);

                        if (it == attack_src_ips.end()) {
                            attack_src_ips.push_back(name);
                        }
                        queueEvent(name, true, false);
                    }
                }
                else if(config.load_model)
                {
                    GroupThresholds threshold = thresholds_map["def"];
                    if(stats_map[name].src_pkts > threshold.src_pkt_thresh or stats_map[name].src_bytes > threshold.src_bytes_thresh or stats_map[name].src_count > threshold.src_count_thresh)
                    {
                        auto it = find(attack_src_ips.begin(), attack_src_ips.end(), name);

                        if (it == attack_src_ips.end()) {
                            attack_src_ips.push_back(name);
                        }
                        queueEvent(name, true, false);
                    }
                }
                found = true;
                break;
            }
        }
    }
    if (!found)
    {
         if(asn_client>0)
        {
            stats_map[to_string(asn_client)].src_pkts += flow->flowstats.client_pkts;
            stats_map[to_string(asn_client)].src_bytes += flow->flowstats.client_bytes;
            stats_map[to_string(asn_client)].src_count++;
            if(proto == PROTO_UDP)
            {
                stats_map[to_string(asn_client)].udp_flows++;
            }
            else if(proto == PROTO_TCP)
            {
                stats_map[to_string(asn_client)].tcp_flows++;
            }
            else if(proto == PROTO_ICMP)
            {
                stats_map[to_string(asn_client)].icmp_flows++;
            }

            src_bytes = flow->flowstats.client_bytes;
            src_pkts = flow->flowstats.client_pkts;
            src_name = to_string(asn_client);
            GroupThresholds threshold = thresholds_map[to_string(asn_client)];

            if(threshold.src_bytes_thresh>0 and threshold.src_pkt_thresh>0 and threshold.src_count_thresh>0)
            {
                if(stats_map[to_string(asn_client)].src_pkts > threshold.src_pkt_thresh or stats_map[to_string(asn_client)].src_bytes > threshold.src_bytes_thresh or stats_map[to_string(asn_client)].src_count > threshold.src_count_thresh)
                {
                    auto it = find(attack_src_ips.begin(), attack_src_ips.end(), to_string(asn_client));

                    if (it == attack_src_ips.end()) {
                        attack_src_ips.push_back(to_string(asn_client));
                    }
                    queueEvent(to_string(asn_client), true, false);
                }
            }
            else if(config.load_model)
            {
                GroupThresholds threshold = thresholds_map["def"];
                if(stats_map[to_string(asn_client)].src_pkts > threshold.src_pkt_thresh or stats_map[to_string(asn_client)].src_bytes > threshold.src_bytes_thresh or stats_map[to_string(asn_client)].src_count > threshold.src_count_thresh)
                {
                    auto it = find(attack_src_ips.begin(), attack_src_ips.end(), to_string(asn_client));

                    if (it == attack_src_ips.end()) {
                        attack_src_ips.push_back(to_string(asn_client));
                    }
                    queueEvent(to_string(asn_client), true, false);
                     
                }
            }
        }
        else
        {
            stats_map[cli_ip_str].src_pkts += flow->flowstats.client_pkts;
            stats_map[cli_ip_str].src_bytes += flow->flowstats.client_bytes;
            stats_map[cli_ip_str].src_count++;
            if(proto == PROTO_UDP)
            {
                stats_map[cli_ip_str].udp_flows++;
            }
            else if(proto == PROTO_TCP)
            {
                stats_map[cli_ip_str].tcp_flows++;
            }
            else if(proto == PROTO_ICMP)
            {
                stats_map[cli_ip_str].icmp_flows++;
            }

            src_bytes = flow->flowstats.client_bytes;
            src_pkts = flow->flowstats.client_pkts;
            src_name = cli_ip_str;

            GroupThresholds threshold = thresholds_map[cli_ip_str];
            
            if(threshold.src_bytes_thresh>0 and threshold.src_pkt_thresh>0 and threshold.src_count_thresh>0)
            {
                if(stats_map[cli_ip_str].src_pkts > threshold.src_pkt_thresh or stats_map[cli_ip_str].src_bytes > threshold.src_bytes_thresh or stats_map[cli_ip_str].src_count > threshold.src_count_thresh)
                {
                    auto it = find(attack_src_ips.begin(), attack_src_ips.end(), cli_ip_str);

                    if (it == attack_src_ips.end()) {
                        attack_src_ips.push_back(cli_ip_str);
                    }
                    queueEvent(cli_ip_str, true, false);
                }
            }
            else if(config.load_model)
            {
                GroupThresholds threshold = thresholds_map["def"];
                if(stats_map[cli_ip_str].src_pkts > threshold.src_pkt_thresh or stats_map[cli_ip_str].src_bytes > threshold.src_bytes_thresh or stats_map[cli_ip_str].src_count > threshold.src_count_thresh)
                {
                    auto it = find(attack_src_ips.begin(), attack_src_ips.end(), cli_ip_str);

                    if (it == attack_src_ips.end()) {
                        attack_src_ips.push_back(cli_ip_str);
                    }
                    queueEvent(cli_ip_str, true, false);       
                        
                }
            }
        }
    }
    
    found = false;
    for (auto& it : config.default_ips)
    {
        string name = it.first;
        vector<const snort::SfCidr*> ip_addresses = it.second;
        for (auto& ip : ip_addresses)
        {
            int comp = ip->contains(&srv_ip);   
             
            if(comp == SFIP_CONTAINS and name!="EXTERNAL_NET")
            {
                stats_mutex.lock();
                if(interval_start_time == 0)
                {
                    interval_start_time = window_start_time;
                }  

                stats_mutex.unlock();
                stats_map[name].dst_pkts += flow->flowstats.server_pkts;
                stats_map[name].dst_bytes += flow->flowstats.server_bytes;
                stats_map[name].dst_count++;
                if(proto == PROTO_UDP)
                {
                    stats_map[name].udp_flows++;
                }
                else if(proto == PROTO_TCP)
                {
                    stats_map[name].tcp_flows++;
                }
                else if(proto == PROTO_ICMP)
                {
                    stats_map[name].icmp_flows++;
                }

                dst_bytes = flow->flowstats.server_bytes;
                dst_pkts = flow->flowstats.server_pkts;
                dst_name = name;

                GroupThresholds threshold = thresholds_map[name];

                if(threshold.dst_bytes_thresh>0 and threshold.dst_pkt_thresh>0 and threshold.dst_count_thresh>0)
                {
                    if(stats_map[name].dst_pkts > threshold.dst_pkt_thresh or stats_map[name].dst_bytes > threshold.dst_bytes_thresh or stats_map[name].dst_count > threshold.dst_count_thresh)
                    {
                        auto it = find(attack_dst_ips.begin(), attack_dst_ips.end(), name);

                        if (it == attack_dst_ips.end()) {
                            attack_dst_ips.push_back(name);
                        }
                        queueEvent(name, false, true);
                    }
                }
                else if(config.load_model)
                {
                    GroupThresholds threshold = thresholds_map["def"];
                    if(stats_map[name].dst_pkts > threshold.dst_pkt_thresh or stats_map[name].dst_bytes > threshold.dst_bytes_thresh or stats_map[name].dst_count > threshold.dst_count_thresh)
                    {
                        auto it = find(attack_dst_ips.begin(), attack_dst_ips.end(), name);

                        if (it == attack_dst_ips.end()) {
                            attack_dst_ips.push_back(name);
                        }
                        queueEvent(name, false, true);
                         
                    }
                }
                found = true;
                break;
            }
        }
    }
    if (!found)
    { 
        if(asn_server>0)
        {
            stats_map[to_string(asn_server)].dst_pkts += flow->flowstats.server_pkts;
            stats_map[to_string(asn_server)].dst_bytes += flow->flowstats.server_bytes;
            stats_map[to_string(asn_server)].dst_count++;
            
            if(proto == PROTO_UDP)
            {
                stats_map[to_string(asn_server)].udp_flows++;
            }
            else if(proto == PROTO_TCP)
            {
                stats_map[to_string(asn_server)].tcp_flows++;
            }
            else if(proto == PROTO_ICMP)
            {
                stats_map[to_string(asn_server)].icmp_flows++;
            }

            dst_bytes = flow->flowstats.server_bytes;
            dst_pkts = flow->flowstats.server_pkts;
            dst_name = to_string(asn_server);
            GroupThresholds threshold = thresholds_map[to_string(asn_server)];
            
            if(threshold.dst_bytes_thresh>0 and threshold.dst_pkt_thresh>0 and threshold.dst_count_thresh>0)
            {
                if(stats_map[to_string(asn_server)].dst_pkts > threshold.dst_pkt_thresh or stats_map[to_string(asn_server)].dst_bytes > threshold.dst_bytes_thresh or stats_map[to_string(asn_server)].dst_count > threshold.dst_count_thresh)
                {
                    auto it = find(attack_dst_ips.begin(), attack_dst_ips.end(), to_string(asn_server));

                    if (it == attack_dst_ips.end()) {
                        attack_dst_ips.push_back(to_string(asn_server));
                    }
                    queueEvent(to_string(asn_server), false, true);
                }
            }
            else if(config.load_model)
            {
                GroupThresholds threshold = thresholds_map["def"];
                if(stats_map[to_string(asn_server)].dst_pkts > threshold.dst_pkt_thresh or stats_map[to_string(asn_server)].dst_bytes > threshold.dst_bytes_thresh or stats_map[to_string(asn_server)].dst_count > threshold.dst_count_thresh)
                {
                    auto it = find(attack_dst_ips.begin(), attack_dst_ips.end(), to_string(asn_server));

                    if (it == attack_dst_ips.end()) {
                        attack_dst_ips.push_back(to_string(asn_server));
                    }
                    queueEvent(to_string(asn_server), false, true);
                    
                }
            }
        }
        else
        {
            stats_map[srv_ip_str].dst_pkts += flow->flowstats.server_pkts;
            stats_map[srv_ip_str].dst_bytes += flow->flowstats.server_bytes;
            stats_map[srv_ip_str].dst_count++;
            if(proto == PROTO_UDP)
            {
                stats_map[srv_ip_str].udp_flows++;
            }
            else if(proto == PROTO_TCP)
            {
                stats_map[srv_ip_str].tcp_flows++;
            }
            else if(proto == PROTO_ICMP)
            {
                stats_map[srv_ip_str].icmp_flows++;
            }

            dst_bytes = flow->flowstats.server_bytes;
            dst_pkts = flow->flowstats.server_pkts;
            dst_name = srv_ip_str;
            GroupThresholds threshold = thresholds_map[srv_ip_str];

            if(threshold.dst_bytes_thresh>0 and threshold.dst_pkt_thresh>0 and threshold.dst_count_thresh>0)
            {
                if(stats_map[srv_ip_str].dst_pkts > threshold.dst_pkt_thresh or stats_map[srv_ip_str].dst_bytes > threshold.dst_bytes_thresh or stats_map[srv_ip_str].dst_count > threshold.dst_count_thresh)
                {
                    auto it = find(attack_dst_ips.begin(), attack_dst_ips.end(), srv_ip_str);

                    if (it == attack_dst_ips.end()) {
                        attack_dst_ips.push_back(srv_ip_str);
                    }
                    queueEvent(srv_ip_str, false, true);
                }
            }
            else if(config.load_model)
            {
                GroupThresholds threshold = thresholds_map["def"];
                if(stats_map[srv_ip_str].dst_pkts > threshold.dst_pkt_thresh or stats_map[srv_ip_str].dst_bytes > threshold.dst_bytes_thresh or stats_map[srv_ip_str].dst_count > threshold.dst_count_thresh)
                {
                    auto it = find(attack_dst_ips.begin(), attack_dst_ips.end(), srv_ip_str);

                    if (it == attack_dst_ips.end()) {
                        attack_dst_ips.push_back(srv_ip_str);
                    }
                    queueEvent(srv_ip_str, false, true);
                     
                }
            }
        }
    }

    bool syn = false;
    if(proto == PROTO_TCP)
    {
        char tcpFlags[9];
        CreateTCPFlagString(p->ptrs.tcph, tcpFlags);
        if(strcmp(tcpFlags, "******S*") == 0)
            syn = true;
    }

    if(!config.training)
        interval_flows.push_back({src_name, dst_name, proto, syn, {src_bytes, src_pkts, dst_bytes, dst_pkts}});
}