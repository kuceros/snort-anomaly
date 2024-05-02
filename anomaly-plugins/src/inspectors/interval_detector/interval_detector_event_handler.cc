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

int counter = 0;

bool model_saved = false;
bool interval_saved = false;

std::vector<float> minMaxScaling(const std::vector<float>& data, const std::vector<float>& minVals, const std::vector<float>& maxVals) {
    std::vector<float> scaledData(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        scaledData[i] = (data[i] - minVals[i]) / (maxVals[i] - minVals[i]);
    }
    return scaledData;
}

void saveModel(std::map<std::string, GroupThreshold>& thresholds_map, int interval, const std::string& filename) {
    std::ofstream outfile(filename, std::ios::binary);
    if (!outfile.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    outfile.write(reinterpret_cast<const char*>(&interval), sizeof(int));
    size_t map_size = thresholds_map.size();
    outfile.write(reinterpret_cast<const char*>(&map_size), sizeof(size_t));

    for (const auto& pair : thresholds_map) {
        size_t key_size = pair.first.size();
        outfile.write(reinterpret_cast<const char*>(&key_size), sizeof(size_t));
        outfile.write(pair.first.data(), key_size);

        outfile.write(reinterpret_cast<const char*>(&pair.second), sizeof(GroupThreshold));
    }
    thresholds_map.clear();
    outfile.close();
}

std::pair<std::map<std::string, GroupThreshold>, int> loadModel(const std::string& filename) {
    std::map<std::string, GroupThreshold> thresholds_map;
    int interval = 0;

    std::ifstream infile(filename, std::ios::binary);
    if (!infile.is_open()) {
        throw std::runtime_error("Error opening file: " + filename);
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

    for (size_t i = 0; i < map_size; ++i) {
        size_t key_size;
        infile.read(reinterpret_cast<char*>(&key_size), sizeof(size_t));
        if (infile.fail()) {
            throw std::runtime_error("Error reading key size from file: " + filename);
        }

        std::string key;
        key.resize(key_size);
        infile.read(&key[0], key_size);
        if (infile.fail()) {
            throw std::runtime_error("Error reading key from file: " + filename);
        }

        GroupThreshold value;
        infile.read(reinterpret_cast<char*>(&value), sizeof(GroupThreshold));
        if (infile.fail()) {
            throw std::runtime_error("Error reading GroupThreshold from file: " + filename);
        }
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
    float normalized_value = (float)(value - 0) / (max_val - 0);
    return normalized_value;
}

void CalcUCL(int window, int interval, int num_sigma){

    for (auto& it : stats_map)
    {
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

        int counter = 0;

        string name = it.first;
        GroupStats stats = it.second;

        stats_map[name].src_pkts_per_inter.push_back(stats_map[name].src_pkts);
        stats_map[name].src_bytes_per_inter.push_back(stats_map[name].src_bytes);
        stats_map[name].dst_pkts_per_inter.push_back(stats_map[name].dst_pkts);
        stats_map[name].dst_bytes_per_inter.push_back(stats_map[name].dst_bytes);
        stats_map[name].dst_count_per_inter.push_back(stats_map[name].dst_count);
        stats_map[name].src_count_per_inter.push_back(stats_map[name].src_count);
        //interval_start_time += interval;
        /*cout<<"name: "<<name<<endl;
        cout<<"src_pkts: "<<stats_map[name].src_pkts<<endl;
        cout<<"src_bytes: "<<stats_map[name].src_bytes<<endl;
        cout<<"dst_pkts: "<<stats_map[name].dst_pkts<<endl;
        cout<<"dst_bytes: "<<stats_map[name].dst_bytes<<endl;
        cout<<"dst_count: "<<stats_map[name].dst_count<<endl;
        cout<<"src_count: "<<stats_map[name].src_count<<endl;
        cout<<endl;*/

        stats_map[name].src_pkts = 0;
        stats_map[name].src_bytes = 0;
        stats_map[name].dst_pkts = 0;
        stats_map[name].dst_bytes = 0;
        stats_map[name].dst_count = 0;
        stats_map[name].src_count = 0;


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
        

        avg_src_bytes = sum_src_bytes / (counter); 
        avg_src_packets = sum_src_packets / counter;
        avg_dst_bytes = sum_dst_bytes / counter;
        avg_dst_packets = sum_dst_packets / counter;
        avg_dst_count = sum_dst_count / counter;
        avg_src_count = sum_src_count /counter;

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

        double varc_src_bytes = dev_src_bytes/counter; //variance
        double std_dev_src_bytes = sqrt(varc_src_bytes); //standard deviation
        double varc_src_packets = dev_src_packets/counter; //variance
        double std_dev_src_packets = sqrt(varc_src_packets); //standard deviation
        double varc_dst_bytes = dev_dst_bytes/counter; //variance
        double std_dev_dst_bytes = sqrt(varc_dst_bytes); //standard deviation
        double varc_dst_packets = dev_dst_packets/counter; //variance
        double std_dev_dst_packets = sqrt(varc_dst_packets); //standard deviation
        double varc_dst_count = dev_dst_count/counter; //variance
        double std_dev_dst_count = sqrt(varc_dst_count); //standard deviation
        double varc_src_count = dev_src_count/counter; //variance
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
    time_t timestamp = seconds;

    struct tm* timeinfo = localtime(&timestamp);

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
        stats_mutex.lock();
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
        stats_mutex.unlock();
    }

    stats_mutex.lock();
    if(window_start_time == 0)
    {
        if(config.load_model and !config.training)
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
            GroupThreshold threshold = thresholds_map[name];

            if(!config.load_model)
            {
                stats_map[name].src_pkts_per_inter.push_back(stats_map[name].src_pkts);
                stats_map[name].src_bytes_per_inter.push_back(stats_map[name].src_bytes);
                stats_map[name].dst_pkts_per_inter.push_back(stats_map[name].dst_pkts);
                stats_map[name].dst_bytes_per_inter.push_back(stats_map[name].dst_bytes);
                stats_map[name].dst_count_per_inter.push_back(stats_map[name].dst_count);
                stats_map[name].src_count_per_inter.push_back(stats_map[name].src_count);
            }

            stats_map[name].src_pkts = 0;
            stats_map[name].src_bytes = 0;
            stats_map[name].dst_pkts = 0;
            stats_map[name].dst_bytes = 0;
            stats_map[name].dst_count = 0;
            stats_map[name].src_count = 0;
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
                it = IntervalFlows.erase(it);
            }
            else if (std::find(attack_dst_ips.begin(), attack_dst_ips.end(), it->dst_ip) != attack_dst_ips.end()) {
             
                std::ostringstream ss;
                
                ss << static_cast<unsigned>(it->proto) << ", " << it->ints[0] << ", " << it->ints[1] << ", " << it->ints[2] << ", " << it->ints[3] << ", 1"<< endl;
                if (!write_to_file(ss.str())) {
                    LogMessage("%s", ss.str().c_str());
                }
                it = IntervalFlows.erase(it);
            } else {
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
        
        IntervalFlows.clear();
        interval_start_time +=config.interval;
    }
    stats_mutex.unlock();

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
                stats_mutex.unlock();
                stats_map[name].src_pkts += flow->flowstats.client_pkts;
                stats_map[name].src_bytes += flow->flowstats.client_bytes;
                stats_map[name].src_count++;

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
                        //cout<<"attack_src: "<<name << " " << stats_map[name].src_bytes << " " << threshold.src_bytes_thresh << " " << stats_map[name].src_pkts << " " << threshold.src_pkt_thresh << " " << stats_map[name].src_count << " " << threshold.src_count_thresh << endl;
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
                        //cout<<"attack_src: "<<name << " " << stats_map[name].src_bytes << " " << threshold.src_bytes_thresh << " " << stats_map[name].src_pkts << " " << threshold.src_pkt_thresh << " " << stats_map[name].src_count << " " << threshold.src_count_thresh << endl;
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
            stats_map[to_string(asn_client)].src_pkts += flow->flowstats.client_pkts;
            stats_map[to_string(asn_client)].src_bytes += flow->flowstats.client_bytes;
            stats_map[to_string(asn_client)].src_count++;


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
                    //cout<<"attack_src: "<<to_string(asn_client) << " " << stats_map[to_string(asn_client)].src_bytes << " " << threshold.src_bytes_thresh << " " << stats_map[to_string(asn_client)].src_pkts << " " << threshold.src_pkt_thresh << " " << stats_map[to_string(asn_client)].src_count << " " << threshold.src_count_thresh << endl;
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
                    //cout<<"attack_src: "<<to_string(asn_client) << " " << stats_map[to_string(asn_client)].src_bytes << " " << threshold.src_bytes_thresh << " " << stats_map[to_string(asn_client)].src_pkts << " " << threshold.src_pkt_thresh << " " << stats_map[to_string(asn_client)].src_count << " " << threshold.src_count_thresh << endl;
                    DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_FROM);
                }
            }
        }
        else
        {
            stats_map[cli_ip_str].src_pkts += flow->flowstats.client_pkts;
            stats_map[cli_ip_str].src_bytes += flow->flowstats.client_bytes;
            stats_map[cli_ip_str].src_count++;

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
                    //cout<<"attack_src: "<<cli_ip_str << " " << stats_map[cli_ip_str].src_bytes << " " << threshold.src_bytes_thresh << " " << stats_map[cli_ip_str].src_pkts << " " << threshold.src_pkt_thresh << " " << stats_map[cli_ip_str].src_count << " " << threshold.src_count_thresh << endl;
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
                    //cout<<"attack_src: "<<cli_ip_str << " " << stats_map[cli_ip_str].src_bytes << " " << threshold.src_bytes_thresh << " " << stats_map[cli_ip_str].src_pkts << " " << threshold.src_pkt_thresh << " " << stats_map[cli_ip_str].src_count << " " << threshold.src_count_thresh << endl;
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

                stats_mutex.unlock();
                stats_map[name].dst_pkts += flow->flowstats.server_pkts;
                stats_map[name].dst_bytes += flow->flowstats.server_bytes;
                stats_map[name].dst_count++;

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
                        //cout<<"attack_dst: "<<name << " " << stats_map[name].dst_bytes << " " << threshold.dst_bytes_thresh << " " << stats_map[name].dst_pkts << " " << threshold.dst_pkt_thresh << " " << stats_map[name].dst_count << " " << threshold.dst_count_thresh << endl;
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
                        //cout<<"attack_dst: "<<name << " " << stats_map[name].dst_bytes << " " << threshold.dst_bytes_thresh << " " << stats_map[name].dst_pkts << " " << threshold.dst_pkt_thresh << " " << stats_map[name].dst_count << " " << threshold.dst_count_thresh << endl;
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
            stats_map[to_string(asn_server)].dst_pkts += flow->flowstats.server_pkts;
            stats_map[to_string(asn_server)].dst_bytes += flow->flowstats.server_bytes;
            stats_map[to_string(asn_server)].dst_count++;

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
                    //cout<<"attack_dst: "<<to_string(asn_server) << " " << stats_map[to_string(asn_server)].dst_bytes << " " << threshold.dst_bytes_thresh << " " << stats_map[to_string(asn_server)].dst_pkts << " " << threshold.dst_pkt_thresh << " " << stats_map[to_string(asn_server)].dst_count << " " << threshold.dst_count_thresh << endl;
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
                    //cout<<"attack_dst: "<<to_string(asn_server) << " " << stats_map[to_string(asn_server)].dst_bytes << " " << threshold.dst_bytes_thresh << " " << stats_map[to_string(asn_server)].dst_pkts << " " << threshold.dst_pkt_thresh << " " << stats_map[to_string(asn_server)].dst_count << " " << threshold.dst_count_thresh << endl;
                    DetectionEngine::queue_event(INTERVAL_DETECTOR_GID, INTERVAL_DETECTOR_TO);
                    //s_counts.anomalies++;
                }
            }
        }
        else
        {
            stats_map[srv_ip_str].dst_pkts += flow->flowstats.server_pkts;
            stats_map[srv_ip_str].dst_bytes += flow->flowstats.server_bytes;
            stats_map[srv_ip_str].dst_count++;

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
                    //cout<<"attack_dst: "<<srv_ip_str << " " << stats_map[srv_ip_str].dst_bytes << " " << threshold.dst_bytes_thresh  << " " << stats_map[srv_ip_str].dst_pkts << " " << threshold.dst_pkt_thresh << " " << stats_map[srv_ip_str].dst_count << " " << threshold.dst_count_thresh << endl;
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
                    //cout<<"attack_dst: "<<srv_ip_str << " " << stats_map[srv_ip_str].dst_bytes << " " << threshold.dst_bytes_thresh  << " " << stats_map[srv_ip_str].dst_pkts << " " << threshold.dst_pkt_thresh << " " << stats_map[srv_ip_str].dst_count << " " << threshold.dst_count_thresh << endl;
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

    if(!config.training)
        IntervalFlows.push_back({src_name, dst_name, proto, {src_bytes, src_pkts, dst_bytes, dst_pkts}});
}