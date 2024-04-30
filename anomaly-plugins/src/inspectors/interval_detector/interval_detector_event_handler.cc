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

using namespace snort;
using namespace std;

mutex stats_mutex;
mutex time_mutex;

uint32_t window_start_time = 0;
uint32_t interval_start_time = 0;
uint32_t train_end_time = 0;

std::map<std::string, GroupStats> stats_map;
std::map<std::string, GroupThreshold> thresholds_map;

std::vector<FlowInfo> IntervalFlows;
std::vector<std::string> attack_src_ips;
std::vector<std::string> attack_dst_ips;

std::vector<float> minMaxScaling(const std::vector<float>& data, const std::vector<float>& minVals, const std::vector<float>& maxVals) {
    std::vector<float> scaledData(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        scaledData[i] = (data[i] - minVals[i]) / (maxVals[i] - minVals[i]);
    }
    return scaledData;
}

void saveModel(const std::map<std::string, GroupThreshold>& thresholds_map, int interval, const std::string& filename) {
    std::ofstream outfile(filename, std::ios::binary);
    if (!outfile.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    outfile.write(reinterpret_cast<const char*>(&interval), sizeof(int));
    // Write the size of the map
    size_t map_size = thresholds_map.size();
    outfile.write(reinterpret_cast<const char*>(&map_size), sizeof(size_t));

    // Iterate over the map and write each key-value pair
    for (const auto& pair : thresholds_map) {
        // Write the length of the key and the key itself
        size_t key_size = pair.first.size();
        outfile.write(reinterpret_cast<const char*>(&key_size), sizeof(size_t));
        outfile.write(pair.first.data(), key_size);

        // Write the GroupThreshold object (assuming it's a POD type)
        outfile.write(reinterpret_cast<const char*>(&pair.second), sizeof(GroupThreshold));
    }

    outfile.close();
}

std::pair<std::map<std::string, GroupThreshold>, int> loadModel(const std::string& filename) {
    std::map<std::string, GroupThreshold> thresholds_map;
    int interval = 0;

    std::ifstream infile(filename, std::ios::binary);
    if (!infile.is_open()) {
        throw std::runtime_error("Error opening file: " + filename);
    }

    // Read the interval from the file
    infile.read(reinterpret_cast<char*>(&interval), sizeof(int));

    // Read the size of the map
    size_t map_size;
    infile.read(reinterpret_cast<char*>(&map_size), sizeof(size_t));

    double sum_src_pkt_thresh = 0.0;
    double sum_src_bytes_thresh = 0.0;
    double sum_dst_pkt_thresh = 0.0;
    double sum_dst_bytes_thresh = 0.0;
    double sum_dst_count_thresh = 0.0;
    double sum_src_count_thresh = 0.0;

    // Iterate over the stored pairs and populate the map
    for (size_t i = 0; i < map_size; ++i) {
        // Read the length of the key
        size_t key_size;
        infile.read(reinterpret_cast<char*>(&key_size), sizeof(size_t));
        if (infile.fail()) {
            throw std::runtime_error("Error reading key size from file: " + filename);
        }

        // Read the key
        std::string key;
        key.resize(key_size);
        infile.read(&key[0], key_size);
        if (infile.fail()) {
            throw std::runtime_error("Error reading key from file: " + filename);
        }

        // Read the GroupThreshold object
        GroupThreshold value;
        infile.read(reinterpret_cast<char*>(&value), sizeof(GroupThreshold));
        if (infile.fail()) {
            throw std::runtime_error("Error reading GroupThreshold from file: " + filename);
        }
        // Insert into the map
        thresholds_map[key] = value;
        sum_src_pkt_thresh += value.src_pkt_thresh;
        sum_src_bytes_thresh += value.src_bytes_thresh;
        sum_dst_pkt_thresh += value.dst_pkt_thresh;
        sum_dst_bytes_thresh += value.dst_bytes_thresh;
        sum_dst_count_thresh += value.dst_count_thresh;
        sum_src_count_thresh += value.src_count_thresh;
    }

    GroupThreshold def_value;
    def_value.src_pkt_thresh = sum_src_pkt_thresh/(int)map_size;
    def_value.src_bytes_thresh = sum_src_bytes_thresh/(int)map_size;
    def_value.dst_pkt_thresh = sum_dst_pkt_thresh/(int)map_size;
    def_value.dst_bytes_thresh = sum_dst_bytes_thresh/(int)map_size;
    def_value.dst_count_thresh = sum_dst_count_thresh/(int)map_size;
    def_value.src_count_thresh = sum_src_count_thresh/(int)map_size;
    thresholds_map["def"] = def_value;

    infile.close();

    return {thresholds_map, interval};
}


float minMaxNormalize(int value, int max_val) {
    // Normalize the value
    float normalized_value = (float)(value - 0) / (max_val - 0);
    return normalized_value;
}

void CalcUCL(int window, int interval, int num_sigma){
    uint64_t sum_src_count = 0;
    uint64_t sum_dst_count = 0;
    uint64_t sum_src_bytes = 0;
    uint64_t sum_src_packets = 0;
    uint64_t sum_dst_bytes = 0;
    uint64_t sum_dst_packets = 0;
    uint64_t avg_src_bytes = 0;
    uint64_t avg_src_packets = 0;
    uint64_t avg_dst_bytes = 0;
    uint64_t avg_dst_packets = 0;
    uint64_t avg_src_count = 0;
    uint64_t avg_dst_count = 0;

    for (auto& it : stats_map)
    {
        string name = it.first;
        GroupStats stats = it.second;

        stats_map[name].src_pkts_per_inter.push_back(stats_map[name].src_pkts);
        stats_map[name].src_bytes_per_inter.push_back(stats_map[name].src_bytes);
        stats_map[name].dst_pkts_per_inter.push_back(stats_map[name].dst_pkts);
        stats_map[name].dst_bytes_per_inter.push_back(stats_map[name].dst_bytes);
        stats_map[name].dst_count_per_inter.push_back(stats_map[name].dst_count);
        stats_map[name].src_count_per_inter.push_back(stats_map[name].src_count);
        //interval_start_time += interval;
        stats_map[name].src_pkts = 0;
        stats_map[name].src_bytes = 0;
        stats_map[name].dst_pkts = 0;
        stats_map[name].dst_bytes = 0;
        stats_map[name].dst_count = 0;
        stats_map[name].src_count = 0;

        for (auto& iter : stats.src_bytes_per_inter)
        {
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

        avg_src_bytes = sum_src_bytes / (window / interval); 
        avg_src_packets = sum_src_packets / (window / interval);
        avg_dst_bytes = sum_dst_bytes / (window / interval);
        avg_dst_packets = sum_dst_packets / (window / interval);
        avg_dst_count = sum_dst_count / (window / interval);
        avg_src_count = sum_src_count / (window / interval);

        double dev_src_bytes = 0;
        double dev_src_packets = 0;
        double dev_dst_bytes = 0;
        double dev_dst_packets = 0;
        double dev_dst_count = 0;
        double dev_src_count = 0;

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

        double varc_src_bytes = dev_src_bytes/(window /interval); //variance
        double std_dev_src_bytes = sqrt(varc_src_bytes); //standard deviation
        double varc_src_packets = dev_src_packets/(window /interval); //variance
        double std_dev_src_packets = sqrt(varc_src_packets); //standard deviation
        double varc_dst_bytes = dev_dst_bytes/(window /interval); //variance
        double std_dev_dst_bytes = sqrt(varc_dst_bytes); //standard deviation
        double varc_dst_packets = dev_dst_packets/(window /interval); //variance
        double std_dev_dst_packets = sqrt(varc_dst_packets); //standard deviation
        double varc_dst_count = dev_dst_count/(window /interval); //variance
        double std_dev_dst_count = sqrt(varc_dst_count); //standard deviation
        double varc_src_count = dev_src_count/(window /interval); //variance
        double std_dev_src_count = sqrt(varc_src_count); //standard deviation

        thresholds_map[name].src_pkt_thresh = avg_src_packets + num_sigma * std_dev_src_packets;
        thresholds_map[name].src_bytes_thresh = avg_src_bytes + num_sigma * std_dev_src_bytes;
        thresholds_map[name].dst_pkt_thresh = avg_dst_packets + num_sigma * std_dev_dst_packets;
        thresholds_map[name].dst_bytes_thresh = avg_dst_bytes + num_sigma * std_dev_dst_bytes;
        thresholds_map[name].dst_count_thresh = avg_dst_count + num_sigma * std_dev_dst_count;
        thresholds_map[name].src_count_thresh = avg_src_count + num_sigma * std_dev_src_count;

    }

    stats_map.clear();
    return;
}

std::string convertSecondsToDateTime(long seconds) {
    // Convert seconds to time_t
    time_t timestamp = seconds;

    // Convert timestamp to a struct tm
    struct tm* timeinfo = localtime(&timestamp);

    // Format timeinfo as a string
    char buffer[80];
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

    return std::string(buffer);
}


bool stringContains(const std::string& mainStr, const std::string& subStr) {
    return mainStr.find(subStr) != std::string::npos;
}

bool checkGroupThresh(const std::map<std::string, GroupThreshold>& thresholds_map, const std::string& name, const GroupStats& stats) {
    GroupThreshold threshold = thresholds_map.at(name);

    if (threshold.src_bytes_thresh > 0 && threshold.src_pkt_thresh > 0 && threshold.src_count_thresh > 0) {
        if (stats.src_pkts > threshold.src_pkt_thresh || stats.src_bytes > threshold.src_bytes_thresh || stats.src_count > threshold.src_count_thresh) {
            return true;
        }
    }

    if (threshold.dst_bytes_thresh > 0 && threshold.dst_pkt_thresh > 0 && threshold.dst_count_thresh > 0) {
        if (stats.dst_pkts > threshold.dst_pkt_thresh || stats.dst_bytes > threshold.dst_bytes_thresh || stats.dst_count > threshold.dst_count_thresh) {
            return true;
        }
    }

    return false;
}

void IntervalDetectorEventHandler::handle(DataEvent& event, Flow* flow)
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
        if (!config.json_logging)
            WarningMessage("appid_listener: flow is null\n");
        return;
    }

    if (!config.json_logging and !appid_changed(ac_bits))
        return;

    char cli_ip_str[INET6_ADDRSTRLEN], srv_ip_str[INET6_ADDRSTRLEN];
    flow->client_ip.ntop(cli_ip_str, sizeof(cli_ip_str));
    flow->server_ip.ntop(srv_ip_str, sizeof(srv_ip_str));
    SfIp cli_ip = flow->client_ip;
    SfIp srv_ip = flow->server_ip;

    MMDB_s my_mmdb;
    int status = MMDB_open(config.db_name.c_str(), MMDB_MODE_MMAP, &my_mmdb);
    if (status != MMDB_SUCCESS) {
        std::cerr << "Error opening ASN database: " << MMDB_strerror(status) << std::endl;
    }
    uint32_t asn_client = 0; // Default value
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

    if(config.training)
    {
        if(train_end_time == 0)
        {
            stats_mutex.lock();
            train_end_time = p->pkth->ts.tv_sec + config.window;
            stats_mutex.unlock();
        }
        if(p->pkth->ts.tv_sec > train_end_time)
        {
            stats_mutex.lock();
            CalcUCL(config.window, config.interval, config.num_sigma);
            saveModel(thresholds_map, config.interval, config.model);
            stats_mutex.unlock();
            return;
        }
    }

    if(window_start_time == 0)
    {
        stats_mutex.lock();
        if(config.load_model)
        {
            try
            {
                std::tie(thresholds_map, config.interval)= loadModel(config.model);
            }
            catch(const std::exception& e)
            {
                std::cerr << e.what() << '\n';
            }
        }
        window_start_time = p->pkth->ts.tv_sec;
        interval_start_time = window_start_time;
        stats_mutex.unlock();
        DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_INTERVAL);
       

    }
    else if(window_start_time+config.window < p->pkth->ts.tv_sec)
    {
        stats_mutex.lock();
        window_start_time += config.window;
        interval_start_time = window_start_time;
        if(!config.load_model)
        {
            CalcUCL(config.window, config.interval, config.num_sigma);
        }
        else
        {
            stats_map.clear();
        }
        stats_mutex.unlock();

        DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_INTERVAL);    
    }

    if(interval_start_time+config.interval < p->pkth->ts.tv_sec)
    {
        for (auto& it : stats_map)
        {
            string name = it.first;
            GroupStats stats = it.second;
            GroupThreshold threshold = thresholds_map[name];

            stats_mutex.lock();
            stats_map[name].src_pkts_per_inter.push_back(stats_map[name].src_pkts);
            stats_map[name].src_bytes_per_inter.push_back(stats_map[name].src_bytes);
            stats_map[name].dst_pkts_per_inter.push_back(stats_map[name].dst_pkts);
            stats_map[name].dst_bytes_per_inter.push_back(stats_map[name].dst_bytes);
            stats_map[name].dst_count_per_inter.push_back(stats_map[name].dst_count);
            stats_map[name].src_count_per_inter.push_back(stats_map[name].src_count);
            stats_mutex.unlock();

            stats_mutex.lock();
            stats_map[name].src_pkts = 0;
            stats_map[name].src_bytes = 0;
            stats_map[name].dst_pkts = 0;
            stats_map[name].dst_bytes = 0;
            stats_map[name].dst_count = 0;
            stats_map[name].src_count = 0;
            stats_mutex.unlock();
        }
        DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_INTERVAL); 

        for (auto it = IntervalFlows.begin(); it != IntervalFlows.end(); ) 
        {

            //cout<<it->src_ip<< " " << it->dst_ip << " " << it->ints[0] << " " << it->ints[1] << " " << it->ints[2] << " " << it->ints[3] << endl; 
            if (std::find(attack_src_ips.begin(), attack_src_ips.end(), it->src_ip) != attack_src_ips.end()) {
                // Print the flow info
                std::ostringstream ss;
                ss << static_cast<unsigned>(it->proto) << ", " << it->ints[0] << ", " << it->ints[1] << ", " << it->ints[2] << ", " << it->ints[3] << ", 1"<< endl;
                if (!write_to_file(ss.str())) {
                    LogMessage("%s", ss.str().c_str());
                }
                // Erase the flow from the vector
                it = IntervalFlows.erase(it);
            }
            // Check if dst_ip is in attack_dst_ips
            else if (std::find(attack_dst_ips.begin(), attack_dst_ips.end(), it->dst_ip) != attack_dst_ips.end()) {
                // Print the flow info
                std::ostringstream ss;
                
                ss << static_cast<unsigned>(it->proto) << ", " << it->ints[0] << ", " << it->ints[1] << ", " << it->ints[2] << ", " << it->ints[3] << ", 1"<< endl;
                if (!write_to_file(ss.str())) {
                    LogMessage("%s", ss.str().c_str());
                }
                // Erase the flow from the vector
                it = IntervalFlows.erase(it);
            } else {
                // Move to the next flow if it doesn't match any attack IP
                std::ostringstream ss;
                ss << static_cast<unsigned>(it->proto) << ", " << it->ints[0] << ", " << it->ints[1] << ", " << it->ints[2] << ", " << it->ints[3] << ", 0"<< endl;
                if (!write_to_file(ss.str())) {
                    LogMessage("%s", ss.str().c_str());
                }
                it = IntervalFlows.erase(it);
            }
        }
        attack_dst_ips.clear();
        attack_src_ips.clear();
        IntervalFlows.clear();
        
        stats_mutex.lock();
        IntervalFlows.clear();
        interval_start_time +=config.interval;
        stats_mutex.unlock();
    }
    bool found = false;
    for (auto& it : config.default_ips)
    {
        string name = it.first;
        std::vector<const snort::SfCidr*> ip_addresses = it.second;
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
                stats_map[name].src_pkts += flow->flowstats.client_pkts;
                stats_map[name].src_bytes += flow->flowstats.client_bytes;
                stats_map[name].src_count++;
                stats_mutex.unlock();

                src_bytes = flow->flowstats.client_bytes;
                src_pkts = flow->flowstats.client_pkts;
                src_name = name;

                GroupThreshold threshold = thresholds_map[name];

                if(threshold.src_bytes_thresh>0 and threshold.src_pkt_thresh>0 and threshold.src_count_thresh>0)
                {
                    if(stats_map[name].src_pkts > threshold.src_pkt_thresh or stats_map[name].src_bytes > threshold.src_bytes_thresh or stats_map[name].src_count > threshold.src_count_thresh)
                    {
                        auto it = std::find(attack_src_ips.begin(), attack_src_ips.end(), name);

                        if (it == attack_src_ips.end()) {
                            attack_src_ips.push_back(name);
                        }
                        DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_FROM);
                    }
                }
                else if(config.load_model)
                {
                    GroupThreshold threshold = thresholds_map["def"];
                    if(stats_map[name].src_pkts > threshold.src_pkt_thresh or stats_map[name].src_bytes > threshold.src_bytes_thresh or stats_map[name].src_count > threshold.src_count_thresh)
                    {
                        auto it = std::find(attack_src_ips.begin(), attack_src_ips.end(), name);

                        if (it == attack_src_ips.end()) {
                            attack_src_ips.push_back(name);
                        }
                        DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_FROM);
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
            stats_mutex.lock();
            stats_map[to_string(asn_client)].src_pkts += flow->flowstats.client_pkts;
            stats_map[to_string(asn_client)].src_bytes += flow->flowstats.client_bytes;
            stats_map[to_string(asn_client)].src_count++;

            stats_mutex.unlock();

            src_bytes = flow->flowstats.client_bytes;
            src_pkts = flow->flowstats.client_pkts;
            src_name = to_string(asn_client);
            GroupThreshold threshold = thresholds_map[to_string(asn_client)];

            if(threshold.src_bytes_thresh>0 and threshold.src_pkt_thresh>0 and threshold.src_count_thresh>0)
            {
                if(stats_map[to_string(asn_client)].src_pkts > threshold.src_pkt_thresh or stats_map[to_string(asn_client)].src_bytes > threshold.src_bytes_thresh or stats_map[to_string(asn_client)].src_count > threshold.src_count_thresh)
                {
                    //setCustomString("custom_string_for_attack_from");
                    auto it = std::find(attack_src_ips.begin(), attack_src_ips.end(), to_string(asn_client));

                    if (it == attack_src_ips.end()) {
                        attack_src_ips.push_back(to_string(asn_client));
                    }
                    DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_FROM);
                }
            }
            else if(config.load_model)
            {
                GroupThreshold threshold = thresholds_map["def"];
                if(stats_map[to_string(asn_client)].src_pkts > threshold.src_pkt_thresh or stats_map[to_string(asn_client)].src_bytes > threshold.src_bytes_thresh or stats_map[to_string(asn_client)].src_count > threshold.src_count_thresh)
                {
                    //setCustomString("custom_string_for_attack_from");
                    auto it = std::find(attack_src_ips.begin(), attack_src_ips.end(), to_string(asn_client));

                    if (it == attack_src_ips.end()) {
                        attack_src_ips.push_back(to_string(asn_client));
                    }
                    DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_FROM);
                }
            }
        }
        else
        {
            stats_mutex.lock();
            stats_map[cli_ip_str].src_pkts += flow->flowstats.client_pkts;
            stats_map[cli_ip_str].src_bytes += flow->flowstats.client_bytes;
            stats_map[cli_ip_str].src_count++;
            stats_mutex.unlock();

            src_bytes = flow->flowstats.client_bytes;
            src_pkts = flow->flowstats.client_pkts;
            src_name = cli_ip_str;

            GroupThreshold threshold = thresholds_map[cli_ip_str];
            
            if(threshold.src_bytes_thresh>0 and threshold.src_pkt_thresh>0 and threshold.src_count_thresh>0)
            {
                if(stats_map[cli_ip_str].src_pkts > threshold.src_pkt_thresh or stats_map[cli_ip_str].src_bytes > threshold.src_bytes_thresh or stats_map[cli_ip_str].src_count > threshold.src_count_thresh)
                {
                    //setCustomString("custom_string_for_attack_from");
                    auto it = std::find(attack_src_ips.begin(), attack_src_ips.end(), cli_ip_str);

                    if (it == attack_src_ips.end()) {
                        attack_src_ips.push_back(cli_ip_str);
                    }
                    DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_FROM);
                }
            }
            else if(config.load_model)
            {
                GroupThreshold threshold = thresholds_map["def"];
                if(stats_map[cli_ip_str].src_pkts > threshold.src_pkt_thresh or stats_map[cli_ip_str].src_bytes > threshold.src_bytes_thresh or stats_map[cli_ip_str].src_count > threshold.src_count_thresh)
                {
                    //setCustomString("custom_string_for_attack_from");
                    auto it = std::find(attack_src_ips.begin(), attack_src_ips.end(), cli_ip_str);

                    if (it == attack_src_ips.end()) {
                        attack_src_ips.push_back(cli_ip_str);
                    }
                    DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_FROM);          
                }
            }
        }
    }
    
    found = false;
    for (auto& it : config.default_ips)
    {
        string name = it.first;
        std::vector<const snort::SfCidr*> ip_addresses = it.second;
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
                stats_map[name].dst_pkts += flow->flowstats.server_pkts;
                stats_map[name].dst_bytes += flow->flowstats.server_bytes;
                stats_map[name].dst_count++;
                stats_mutex.unlock();

                dst_bytes = flow->flowstats.server_bytes;
                dst_pkts = flow->flowstats.server_pkts;
                dst_name = name;

                GroupThreshold threshold = thresholds_map[name];

                if(threshold.dst_bytes_thresh>0 and threshold.dst_pkt_thresh>0 and threshold.dst_count_thresh>0)
                {
                    if(stats_map[name].dst_pkts > threshold.dst_pkt_thresh or stats_map[name].dst_bytes > threshold.dst_bytes_thresh or stats_map[name].dst_count > threshold.dst_count_thresh)
                    {
                        auto it = std::find(attack_dst_ips.begin(), attack_dst_ips.end(), name);

                        if (it == attack_dst_ips.end()) {
                            attack_dst_ips.push_back(name);
                        }
                        DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_TO);
                    }
                }
                else if(config.load_model)
                {
                    GroupThreshold threshold = thresholds_map["def"];
                    if(stats_map[name].dst_pkts > threshold.dst_pkt_thresh or stats_map[name].dst_bytes > threshold.dst_bytes_thresh or stats_map[name].dst_count > threshold.dst_count_thresh)
                    {
                        auto it = std::find(attack_dst_ips.begin(), attack_dst_ips.end(), name);

                        if (it == attack_dst_ips.end()) {
                            attack_dst_ips.push_back(name);
                        }
                        DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_TO);
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
            stats_mutex.lock();
            stats_map[to_string(asn_server)].dst_pkts += flow->flowstats.server_pkts;
            stats_map[to_string(asn_server)].dst_bytes += flow->flowstats.server_bytes;
            stats_map[to_string(asn_server)].dst_count++;

            stats_mutex.unlock();

            dst_bytes = flow->flowstats.server_bytes;
            dst_pkts = flow->flowstats.server_pkts;
            dst_name = to_string(asn_server);
            GroupThreshold threshold = thresholds_map[to_string(asn_server)];
            
            if(threshold.dst_bytes_thresh>0 and threshold.dst_pkt_thresh>0 and threshold.dst_count_thresh>0)
            {
                if(stats_map[to_string(asn_server)].dst_pkts > threshold.dst_pkt_thresh or stats_map[to_string(asn_server)].dst_bytes > threshold.dst_bytes_thresh or stats_map[to_string(asn_server)].dst_count > threshold.dst_count_thresh)
                {
                    //setCustomString("custom_string_for_attack_to");
                    auto it = std::find(attack_dst_ips.begin(), attack_dst_ips.end(), to_string(asn_server));

                    if (it == attack_dst_ips.end()) {
                        attack_dst_ips.push_back(to_string(asn_server));
                    }
                    DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_TO);
                    //s_counts.anomalies++;
                }
            }
            else if(config.load_model)
            {
                GroupThreshold threshold = thresholds_map["def"];
                if(stats_map[to_string(asn_server)].dst_pkts > threshold.dst_pkt_thresh or stats_map[to_string(asn_server)].dst_bytes > threshold.dst_bytes_thresh or stats_map[to_string(asn_server)].dst_count > threshold.dst_count_thresh)
                {
                    //setCustomString("custom_string_for_attack_to");
                    auto it = std::find(attack_dst_ips.begin(), attack_dst_ips.end(), to_string(asn_server));

                    if (it == attack_dst_ips.end()) {
                        attack_dst_ips.push_back(to_string(asn_server));
                    }
                    DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_TO);
                    //s_counts.anomalies++;
                }
            }
        }
        else
        {
            stats_mutex.lock();
            stats_map[srv_ip_str].dst_pkts += flow->flowstats.server_pkts;
            stats_map[srv_ip_str].dst_bytes += flow->flowstats.server_bytes;
            stats_map[srv_ip_str].dst_count++;

            stats_mutex.unlock();

            dst_bytes = flow->flowstats.server_bytes;
            dst_pkts = flow->flowstats.server_pkts;
            dst_name = srv_ip_str;
            GroupThreshold threshold = thresholds_map[srv_ip_str];

            if(threshold.dst_bytes_thresh>0 and threshold.dst_pkt_thresh>0 and threshold.dst_count_thresh>0)
            {
                if(stats_map[srv_ip_str].dst_pkts > threshold.dst_pkt_thresh or stats_map[srv_ip_str].dst_bytes > threshold.dst_bytes_thresh or stats_map[srv_ip_str].dst_count > threshold.dst_count_thresh)
                {
                    //setCustomString("custom_string_for_attack_to");
                    auto it = std::find(attack_dst_ips.begin(), attack_dst_ips.end(), srv_ip_str);

                    if (it == attack_dst_ips.end()) {
                        attack_dst_ips.push_back(srv_ip_str);
                    }
                    DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_TO);
                    //s_counts.anomalies++;
                }
            }
            else if(config.load_model)
            {
                GroupThreshold threshold = thresholds_map["def"];
                if(stats_map[srv_ip_str].dst_pkts > threshold.dst_pkt_thresh or stats_map[srv_ip_str].dst_bytes > threshold.dst_bytes_thresh or stats_map[srv_ip_str].dst_count > threshold.dst_count_thresh)
                {
                    //setCustomString("custom_string_for_attack_to");
                    auto it = std::find(attack_dst_ips.begin(), attack_dst_ips.end(), srv_ip_str);

                    if (it == attack_dst_ips.end()) {
                        attack_dst_ips.push_back(srv_ip_str);
                    }
                    DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_TO);
                    //s_counts.anomalies++;
                }
            }
        }
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

    IntervalFlows.push_back({src_name, dst_name, proto, {src_bytes, src_pkts, dst_bytes, dst_pkts}});
}

void IntervalDetectorEventHandler::print_message(const char* cli_ip_str, const char* srv_ip_str,
    const Flow& flow, PegCount packet_num, AppId service, AppId client, AppId payload, AppId misc,
    AppId referred)
{
    print_header(cli_ip_str, srv_ip_str, flow.client_port, flow.server_port, flow.ip_proto,
        packet_num);

    ostringstream ss;
    ss << " service: " << service << " client: " << client << " payload: " <<
        payload << " misc: " << misc << " referred: " << referred << endl;

    if (!write_to_file(ss.str()))
        LogMessage("%s", ss.str().c_str());
}

void IntervalDetectorEventHandler::print_json_message(JsonStream& js, const char* cli_ip_str, uint32_t asn,
    const char* srv_ip_str, const Flow& flow, PegCount packet_num, const AppIdSessionApi& api,
    AppId service, AppId client, AppId payload, AppId misc, AppId referred,
    bool is_httpx, uint32_t httpx_stream_index, const Packet* p, const char* netbios_name,
    const char* netbios_domain)
{
    assert(p);
    

    js.close();
    js.close();
}
