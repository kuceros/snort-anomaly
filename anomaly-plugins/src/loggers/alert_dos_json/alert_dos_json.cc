//--------------------------------------------------------------------------
// Copyright (C) 2017-2024 Cisco and/or its affiliates. All rights reserved.
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

// alert_json.cc author Russ Combs <rucombs@cisco.com>
//

// preliminary version based on hacking up alert_csv.cc.  should probably
// share a common implementation class.

// if a more sophisticated solution is needed, for example to escape \ or
// whatever, look at this from Joel: https://github.com/jncornett/alert_json,
// which is also more OO implemented.  should pull in that at some point.

// modified alert_dos_json.cc by Rostislav Kucera <kucera.rosta@gmail.com>, 2024

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <fstream>

#include <maxminddb.h>

#include "detection/detection_engine.h"
#include "detection/signature.h"
#include "events/event.h"
#include "flow/flow_key.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "helpers/base64_encoder.h"
#include "log/log.h"
#include "log/log_text.h"
#include "log/text_log.h"
#include "log/messages.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "protocols/cisco_meta_data.h"
#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"
#include "utils/stats.h"

#include "helpers/json_stream.h"

using namespace snort;
using namespace std;

#define LOG_BUFFER (4*K_BYTES)

static THREAD_LOCAL TextLog* json_log;

#define S_NAME "alert_dos_json"
#define F_NAME S_NAME ".txt"
#define MAX_UINT32_DIGITS 12 

struct sid_stats {
    uint32_t sid;
    int count;
};

struct ip_entry {
    string ipAddress;
    int count;
};

/**
 * necessary default Snort structures for loading default IP groups
 */
typedef struct _ip_node
{
    snort::SfCidr* ip = nullptr;
    struct _ip_node* next = nullptr;
    int flags = 0;
    int addr_flags = 0;
} sfip_node_t;

struct sfip_var_t
{
    sfip_node_t* head;
    sfip_node_t* neg_head;
    sfip_var_t* next;

    uint32_t head_count;
    uint32_t neg_head_count;
    uint32_t id;
    char* name;
    char* value;
};

struct vartable_t
{
    sfip_var_t* head;
    uint32_t id;
};

struct Mitre{
    string classtype;
    string direction;
    string TActic;
    string Technique;
    string Tname;
    string TA_inb;
    string T_inb;
    string TA_lat;
    string T_lat;
    string TA_out;
    string T_out;
    string msg;
    string reference;
};

static const Parameter s_params[] =
{
    { "mapping", Parameter::PT_STRING, nullptr, "false",
      "csv file of rule-mitre mapping" },
    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },
    { "db", Parameter::PT_STRING, nullptr, nullptr,
        "input GeoLite2 ASN database" },
    { "interval", Parameter::PT_BOOL, nullptr, "false",
      "logging interval module output" },
    { "flow_ml", Parameter::PT_BOOL, nullptr, "false",
      "logging flow_ml module output" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event with mitre in json format"

class DoSJsonModule : public Module
{
public:
    DoSJsonModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return GLOBAL; }

public:
    bool file = false;
    string mapping = "";
    map<int, Mitre> rules_map;
    int limit = 0;
    const char* fields = nullptr;
    const char* sep = ",";
    bool interval;
    bool ml;
    std::string db_name;
};

/**
 * This function checks the name of the provided value and sets the corresponding configuration value. 
 * If the name is "mapping", the mapping configuration value is set. 
 * If the name is "file", the file configuration value is set. 
 * If the name is "db", the db_name configuration value is set.
 * 
 * return: Always returns true.
 */
bool DoSJsonModule::set(const char*, Value& v, SnortConfig*)
{
    if(v.is("mapping"))
        mapping = v.get_string();
    else if ( v.is("file") )
        file = v.get_bool();
    else if ( v.is("db") )
        db_name = v.get_string();
    else if ( v.is("interval") )
        interval = v.get_bool();
    else if ( v.is("flow_ml") )
        ml = v.get_bool();

    return true;
}

/**
 * This function is not yet implemented.
 * 
 * return: returns true.
 */
bool DoSJsonModule::begin(const char*, int, SnortConfig* sc)
{
    mapping = "";
    file = false;
    db_name="";
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class DoSJsonLogger : public Logger
{
public:
    DoSJsonLogger(DoSJsonModule*);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, const Event&) override;

    bool containsIP(std::vector<ip_entry>& vec, string ipAddress) {
        for (const auto& entry : vec) {
            if (entry.ipAddress == ipAddress) {
                return true;
            }
        }
        return false;
    }

    /**
     * This function takes a long integer representing seconds since the epoch (1970-01-01 00:00:00) 
     * and converts it to a string representing the date and time in the format "YYYY-MM-DD HH:MM:SS".
     * 
     * seconds: The number of seconds since the epoch.
     * return: The formatted date-time string.
     */
    std::string convertSecondsToDateTime(long seconds) {
        time_t timestamp = seconds;

        struct tm* timeinfo = localtime(&timestamp);

        char buffer[80];
        strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

        return std::string(buffer);
    }

    /**
     * This function checks if the provided string is enclosed in triple quotes. 
     * If it is, the function returns the string without the enclosing triple quotes. 
     * If the string is not enclosed in triple quotes, the function returns the original string.
     * 
     * str: The string from which to extract the message.
     * return: The extracted message.
     */
    std::string extractMsg(const std::string& str) {
        if (str.size() >= 6 && str.substr(0, 3) == "\"\"\"" && str.substr(str.size() - 3) == "\"\"\"") {
            return str.substr(3, str.size() - 6);
        }
        return str;
    }

    /**
     * This function checks if the provided string is enclosed in quotes. 
     * If it is, the function returns the string without the enclosing quotes. 
     * If the string is not enclosed in quotes, the function returns the original string.
     * 
     * str: The string from which to extract the reference.
     * return: The extracted reference.
     */
    std::string extractRef(const std::string& str) {
        if (str.size() >= 2 && str.substr(0, 1) == "\"" && str.substr(str.size() - 1) == "\"") {
            return str.substr(1, str.size() - 2);
        }
        return str;
    }

    /**
     * This function takes an integer representing a protocol and returns a string representation of that protocol. The function currently supports ICMP (1), IGMP (2), TCP (6), and UDP (17). If the provided integer does not match any of these, the function returns an empty string.
     * 
     * ip_proto: The integer representing the protocol.
     * return: The string representation of the protocol.
     */
    std::string get_proto_str(uint8_t ip_proto)
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

    /**
     * Function uses the MaxMind DB to look up the ASN for a given IP address. The function returns the ASN as a 32-bit unsigned integer.
     * 
     * ip: The IP address for which to retrieve the ASN.
     * my_mmdb: The MaxMind DB to use for the lookup.
     * return: The ASN for the given IP address.
     */
    uint32_t getASN(const char* ip, MMDB_s my_mmdb)
    {
        uint32_t asn = 0;
        MMDB_lookup_result_s result;
        int error;
        int db_error;

        result = MMDB_lookup_string(&my_mmdb, ip, &error, &db_error);

        MMDB_entry_data_s entry_data;
        if (result.found_entry && MMDB_get_value(&result.entry, &entry_data, "autonomous_system_number", NULL) == MMDB_SUCCESS) {
            if (entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UINT32) {
                asn = entry_data.uint32;
            }
        }

        return asn;
    }

public:
    string file;
    string mapping;
    map<int, Mitre> rules_map;
    int limit;
    const char* fields;
    const char* sep;
    std::string db_name;
    map<string, vector<const snort::SfCidr*>> default_ips;
    MMDB_s my_mmdb;
    int db_status;
    bool ml = false;
    bool interval = false;
    unsigned int inter_start = 0;

    std::vector<ip_entry> srcVec;
    std::vector<ip_entry> dstVec;

    std::vector<string> srcPrint;
    std::vector<string> dstPrint;

    std::vector<sid_stats> sidStats;

    bool udp = false;
    bool tcp = false;
    bool icmp = false;

};

/**
 * This constructor initializes the DoSJsonLogger with the parameters defined in the provided DoSJsonModule. 
 * It also opens the MITRE ATT&CK mapping file and reads its contents line by line, extracting the sid, proto, source, 
 * src_port, arrow, destination, and dst_port from each line.
 * 
 * m: The DoSJsonModule from which to initialize the DoSJsonLogger.
 */
DoSJsonLogger::DoSJsonLogger(DoSJsonModule* m) : file(m->file ? F_NAME : "stdout"), limit(m->limit), fields(std::move(m->fields)), sep(m->sep), db_name(m->db_name), interval(m->interval), ml(m->ml)
{ 
    string file_in = m->mapping; 
    ifstream map_file(file_in);

    if (!map_file.is_open()) {
        ErrorMessage("Error opening mapping file");
        return ;
    }

    string line;
    getline(map_file, line);
    while (getline(map_file, line)) {
        istringstream ss(line);

        string sid, proto, source, src_port, destination, dst_port, classtype, direction, TActic, Technique, Tname, TA_inb, T_inb, TA_lat, T_lat, TA_out, T_out, msg, reference, arrow;
        char comma;

        
        if (std::getline(ss, sid, ',') && 
            std::getline(ss, proto, ',') && 
            std::getline(ss, source, ',') &&  
            std::getline(ss, src_port, ',') && 
            std::getline(ss, arrow, ',') && 
            std::getline(ss, destination, ',') && 
            std::getline(ss, dst_port, ',') && 
            std::getline(ss, classtype, ',') && 
            std::getline(ss, direction, ',') && 
            std::getline(ss, TActic, ',') && 
            std::getline(ss, Technique, ',') && 
            std::getline(ss, Tname, ',') && 
            std::getline(ss, TA_inb, ',') && 
            std::getline(ss, T_inb, ',') && 
            std::getline(ss, TA_lat, ',') && 
            std::getline(ss, T_lat, ',') && 
            std::getline(ss, TA_out, ',') && 
            std::getline(ss, T_out, ',') && 
            std::getline(ss, msg, ',')) { 

            if (std::getline(ss, reference, '\n')) {
            } else {
                reference = ""; 
            }

            Mitre mitre_data;
            mitre_data.classtype = classtype;
            mitre_data.direction = direction;
            mitre_data.TActic = TActic;
            mitre_data.Technique = Technique;
            mitre_data.Tname = Tname;
            mitre_data.TA_inb = TA_inb;
            mitre_data.T_inb = T_inb;
            mitre_data.TA_lat = TA_lat;
            mitre_data.T_lat = T_lat;
            mitre_data.TA_out = TA_out;
            mitre_data.T_out = T_out;
            mitre_data.msg = extractMsg(msg);
            mitre_data.reference = extractRef(reference);
            rules_map[std::stoi(sid)] = mitre_data;
        }
    }  
    map_file.close();
}

/**
 * This function initializes the JSON log with the file name, log buffer size, and limit specified in the DoSJsonLogger. 
 * It then retrieves the IP addresses from the IP variable table and stores them in the default_ips map.
 */
void DoSJsonLogger::open()
{
    json_log = TextLog_Init(file.c_str(), LOG_BUFFER, limit);
    char ip[INET6_ADDRSTRLEN];
    sfip_var_t* it_var = get_ips_policy()->ip_vartable->head;

    while (it_var)
    {
        vector<const snort::SfCidr*> ip_addresses;
        std::string name = it_var->name;
        _ip_node* it_node = it_var->head;
        while (it_node)
        {
            const snort::SfCidr* ip = it_node->ip;
            ip_addresses.push_back(ip);
            it_node = it_node->next;
        }
        default_ips[name] = ip_addresses;
        it_var = it_var->next;
    }

    db_status = MMDB_open(db_name.c_str(), MMDB_MODE_MMAP, &my_mmdb);
    if (db_status != MMDB_SUCCESS and strcmp(db_name.c_str(), "") != 0){
        WarningMessage("%s\n", MMDB_strerror(db_status));
    }

}

/**
 * This function checks if the JSON log has been initialized. If it has, the function terminates the JSON log. 
 * The function also checks if the MaxMind DB has been opened successfully. If it has, the function closes the DB.
 */
void DoSJsonLogger::close()
{
    if ( json_log )
        TextLog_Term(json_log);
    
    if (db_status == MMDB_SUCCESS)
        MMDB_close(&my_mmdb);
    
}

/**
 * This function extracts the client and server IP addresses from the provided packet. 
 * If the packet is associated with a flow, the function also retrieves the client and server Autonomous System Numbers (ASNs)
 * from the MaxMind DB. The function then logs the alert details in JSON format.
 * It handles alerts from IntervalDetector - with MITRE ATTACK infos 
 * and FlowML module.
 * 
 * 
 *
 * p: The packet associated with the event.
 * msg: The message to be displayed.
 * event: The event to be alerted.
 */
void DoSJsonLogger::alert(Packet* p, const char* msg, const Event& event)
{
    char cli_ip_str[INET6_ADDRSTRLEN], srv_ip_str[INET6_ADDRSTRLEN];
    snort::SfIp cli_ip;
    snort::SfIp srv_ip;
    if(p->flow != nullptr){
        p->flow->client_ip.ntop(cli_ip_str, sizeof(cli_ip_str));
        cli_ip = p->flow->client_ip;
        srv_ip = p->flow->server_ip;
        p->flow->server_ip.ntop(srv_ip_str, sizeof(srv_ip_str));
    }

    uint32_t asn_client = 0; // Default value
    uint32_t asn_server = 0;
    if(event.sig_info->gid == 1 or event.sig_info->gid == 666 or event.sig_info->gid == 667 or event.sig_info->gid == 129)
    {
        if(db_status == MMDB_SUCCESS)
        {
            
            asn_client = getASN(cli_ip_str, my_mmdb);
            asn_server = getASN(srv_ip_str, my_mmdb);
        }
        else if(db_status != MMDB_SUCCESS and strcmp(db_name.c_str(), "") != 0)
        {
            WarningMessage("%s\n", MMDB_strerror(db_status));
        }
    }

    if(event.sig_info->gid == 1)
    {
        string group_cli;
        bool found = false;
        for (auto& it : default_ips)
        {
            string name = it.first;
            std::vector<const snort::SfCidr*> ip_addresses = it.second;
            for (auto& ip : ip_addresses)
            {
                int comp = ip->contains(&cli_ip);
                if(comp == SFIP_CONTAINS and name!="EXTERNAL_NET")
                {
                    group_cli = name;
                    found = true;
                    break;
                }
            }
        }
        if(!found)
        {
            if(asn_client>0)
            {
                group_cli = to_string(asn_client);
            }
            else
            {
                group_cli = cli_ip_str;
            }
        }

        string group_srv;
        found = false;
        for (auto& it : default_ips)
        {
            string name = it.first;
            std::vector<const snort::SfCidr*> ip_addresses = it.second;
            for (auto& ip : ip_addresses)
            {
                int comp = ip->contains(&srv_ip);
                if(comp == SFIP_CONTAINS and name!="EXTERNAL_NET")
                {
                    group_srv = name;
                    found = true;
                    break;
                }
            }
        }
        if(!found)
        {
            if(asn_server>0)
            {
                group_srv = to_string(asn_server);
            }
            else
            {
                group_srv = srv_ip_str;
            }
        }

        if(p->has_ip() and containsIP(srcVec, group_cli))
        {
            auto it = std::find_if(sidStats.begin(), sidStats.end(), [&](const sid_stats& entry) {
                return entry.sid == event.sig_info->sid;
            });

            if (it != sidStats.end()) {
                // If the IP address is found, increment the count
                it->count++;
            }
            else
            {
                // If the IP address is not found, add a new entry to the vector
                sidStats.push_back({event.sig_info->sid, 1});
            }
        }
        else if(p->has_ip() and containsIP(dstVec, group_srv))
        {
            auto it = std::find_if(sidStats.begin(), sidStats.end(), [&](const sid_stats& entry) {
                return entry.sid == event.sig_info->sid;
            });

            if (it != sidStats.end()) {
                // If the IP address is found, increment the count
                it->count++;
            }
            else
            {
                // If the IP address is not found, add a new entry to the vector
                sidStats.push_back({event.sig_info->sid, 1});
            }
        }
    }
    
    if(event.sig_info->gid == 666 and interval)
    {
        if(event.sig_info->sid == 1)
        {
            for (const auto& entry : srcVec) {
                    
                    if (std::find(srcPrint.begin(), srcPrint.end(), entry.ipAddress) == srcPrint.end()) {
                        srcPrint.push_back(entry.ipAddress);
                    }
            }
            
            for (const auto& entry : dstVec) {

                if (std::find(dstPrint.begin(), dstPrint.end(), entry.ipAddress) == dstPrint.end()) {
                    dstPrint.push_back(entry.ipAddress);
                }
        
            }

            std::ostringstream ss;
            JsonStream js(ss);
            if(!srcVec.empty() or !dstVec.empty())
            {
                js.open();
                js.put("detection", "IntervalDetector");
                js.put("start_time", convertSecondsToDateTime(inter_start));
                js.put("end_time", convertSecondsToDateTime(p->pkth->ts.tv_sec));
                if(udp)
                    js.put("proto", "UDP");
                if(tcp)
                    js.put("proto", "TCP");
                if(icmp)
                    js.put("proto", "ICMP");
            }
            if(!srcVec.empty())
            {
                js.open("src");
                for (const auto& ip : srcPrint) {

                    js.put("group", ip);
                }
                js.close();
            }
            if(!dstVec.empty())
            {
                js.open("dst");
                for (const auto& ip : dstPrint) {
                    js.put("group", ip);
                }
                js.close();
            }
            if(!sidStats.empty())
            {
                auto maxCountEntry = std::max_element(sidStats.begin(), sidStats.end(), 
                    [](const sid_stats& a, const sid_stats& b) {
                        return a.count < b.count;
                    });
                struct Mitre m = rules_map[maxCountEntry->sid];
                js.open("mitre");
                js.put("sid", maxCountEntry->sid);
                if(m.classtype != "")
                    js.put("classtype", m.classtype);
                if(m.direction != "")
                    js.put("direction", m.direction);
                if(m.TActic != "")
                    js.put("TActic", m.TActic);
                if(m.Technique != "")
                    js.put("Technique", m.Technique);
                if(m.Tname != "")
                    js.put("Tname", m.Tname);
                if(m.TA_inb != "")
                    js.put("TA_inb", m.TA_inb);
                if(m.T_inb != "")
                    js.put("T_inb", m.T_inb);
                if(m.TA_lat != "")
                    js.put("TA_lat", m.TA_lat);
                if(m.T_lat != "")
                    js.put("T_lat", m.T_lat);
                if(m.TA_out != "")
                    js.put("TA_out", m.TA_out);
                if(m.T_out != "")
                    js.put("T_out", m.T_out);
                if(m.msg != "")
                    js.put("msg", m.msg);
                if(m.reference != "")
                    js.put("reference", m.reference);
                js.close();
                
            }
            if(!srcVec.empty() or !dstVec.empty())
            {
                js.close();
            }
            std::ofstream file_stream;
            file_stream.open("alert_dos_json.txt", std::ios_base::app);

            if (file_stream.is_open()) {
                file_stream << ss.str();
                file_stream.close();
            }
            else {
                WarningMessage("%s\n", "Error opening file");
            }

            icmp = false;
            tcp = false;
            udp = false;
            srcVec.clear();
            dstVec.clear();
            sidStats.clear();
            srcPrint.clear();
            dstPrint.clear();
            inter_start = p->pkth->ts.tv_sec;
        }
        
        if (event.sig_info->sid == 2 or event.sig_info->sid == 3 or event.sig_info->sid == 4 or event.sig_info->sid == 5)
        {
            if(event.sig_info->sid == 2)
            {
                udp = true;
            }
            if(event.sig_info->sid == 3)
            {
                tcp = true;
            }
            if(event.sig_info->sid == 4)
            {
                icmp = true;
            }

            bool found = false;
            for (auto& it : default_ips)
            {
                string name = it.first;
                std::vector<const snort::SfCidr*> ip_addresses = it.second;
                for (auto& ip : ip_addresses)
                {
                    int comp = ip->contains(&cli_ip);
                    if(comp == SFIP_CONTAINS and name!="EXTERNAL_NET")
                    {
                        auto it = std::find_if(srcVec.begin(), srcVec.end(), [&](const ip_entry& entry) {
                            return entry.ipAddress == name;
                        });
                        if (it != srcVec.end()) {
                            // If the IP address is found, increment the count
                            it->count++;
                        } else {
                            // If the IP address is not found, add a new entry to the vector
                            srcVec.push_back({name, 1});
                        }
                        found = true;
                        break;
                    }
                }
            }
            if(!found)
            {
                if(asn_client>0)
                {
                    auto it = std::find_if(srcVec.begin(), srcVec.end(), [&](const ip_entry& entry) {
                        return entry.ipAddress == to_string(asn_client);
                    });
                    if (it != srcVec.end()) {
                        // If the IP address is found, increment the count
                        it->count++;
                    } else {
                        // If the IP address is not found, add a new entry to the vector
                        srcVec.push_back({to_string(asn_client), 1});
                    }
                }
                else
                {
                    auto it = std::find_if(srcVec.begin(), srcVec.end(), [&](const ip_entry& entry) {
                        return entry.ipAddress == cli_ip_str;
                    });
                    if (it != srcVec.end()) {
                        // If the IP address is found, increment the count
                        it->count++;
                    } else {
                        // If the IP address is not found, add a new entry to the vector
                        srcVec.push_back({cli_ip_str, 1});
                    }
                }
            }

            found = false;
            for (auto& it : default_ips)
            {
                string name = it.first;
                std::vector<const snort::SfCidr*> ip_addresses = it.second;
                for (auto& ip : ip_addresses)
                {
                    int comp = ip->contains(&srv_ip);
                    if(comp == SFIP_CONTAINS and name!="EXTERNAL_NET")
                    {
                        auto it = std::find_if(dstVec.begin(), dstVec.end(), [&](const ip_entry& entry) {
                            return entry.ipAddress == name;
                        });
                        if (it != dstVec.end()) {
                            // If the IP address is found, increment the count
                            it->count++;
                        } else {
                            // If the IP address is not found, add a new entry to the vector
                            dstVec.push_back({name, 1});
                        }
                        found = true;
                        break;
                    }
                }
            }
            if(!found)
            {
                if(asn_server>0)
                {
                    auto it = std::find_if(dstVec.begin(), dstVec.end(), [&](const ip_entry& entry) {
                        return entry.ipAddress == to_string(asn_server);
                    });
                    if (it != dstVec.end()) {
                        // If the IP address is found, increment the count
                        it->count++;
                    } else {
                        // If the IP address is not found, add a new entry to the vector
                        dstVec.push_back({to_string(asn_server), 1});
                    }
                }
                else
                {
                    auto it = std::find_if(dstVec.begin(), dstVec.end(), [&](const ip_entry& entry) {
                        return entry.ipAddress == srv_ip_str;
                    });
                    if (it != dstVec.end()) {
                        // If the IP address is found, increment the count
                        it->count++;
                    } else {
                        // If the IP address is not found, add a new entry to the vector
                        dstVec.push_back({srv_ip_str, 1});
                    }
                }
            }
        }

        if (event.sig_info->sid == 6 or event.sig_info->sid == 7 or event.sig_info->sid == 8 or event.sig_info->sid == 9)
        {
            if(event.sig_info->sid == 6)
            {
                udp = true;
            }
            if(event.sig_info->sid == 7)
            {
                tcp = true;
            }
            if(event.sig_info->sid == 8)
            {
                icmp = true;
            }

            bool found = false;
            for (auto& it : default_ips)
            {
                string name = it.first;
                std::vector<const snort::SfCidr*> ip_addresses = it.second;
                for (auto& ip : ip_addresses)
                {
                    int comp = ip->contains(&srv_ip);
                    if(comp == SFIP_CONTAINS and name!="EXTERNAL_NET")
                    {
                        auto it = std::find_if(dstVec.begin(), dstVec.end(), [&](const ip_entry& entry) {
                            return entry.ipAddress == name;
                        });
                        if (it != dstVec.end()) {
                            // If the IP address is found, increment the count
                            it->count++;
                        } else {
                            // If the IP address is not found, add a new entry to the vector
                            dstVec.push_back({name, 1});
                        }
                        found = true;
                        break;
                    }
                }
            }
            if(!found)
            {
                if(asn_server>0)
                {
                    auto it = std::find_if(dstVec.begin(), dstVec.end(), [&](const ip_entry& entry) {
                        return entry.ipAddress == to_string(asn_server);
                    });
                    if (it != dstVec.end()) {
                        // If the IP address is found, increment the count
                        it->count++;
                    } else {
                        // If the IP address is not found, add a new entry to the vector
                        dstVec.push_back({to_string(asn_server), 1});
                    }
                }
                else
                {
                    auto it = std::find_if(dstVec.begin(), dstVec.end(), [&](const ip_entry& entry) {
                        return entry.ipAddress == srv_ip_str;
                    });
                    if (it != dstVec.end()) {
                        // If the IP address is found, increment the count
                        it->count++;
                    } else {
                        // If the IP address is not found, add a new entry to the vector
                        dstVec.push_back({srv_ip_str, 1});
                    }
                }
            }
        }
    }
    if(event.sig_info->gid ==667 and ml)
    {
        if(event.sig_info->sid == 1)
        {
            std::ostringstream ss;
            JsonStream js(ss);
            js.open();
            js.put("detection", "FlowML");
            js.put("timestamp", convertSecondsToDateTime(p->pkth->ts.tv_sec));
            if(p->is_ip())
            {
                if(get_proto_str(p->flow->ip_proto)!="0")
                    js.put("proto", get_proto_str(p->flow->ip_proto));
            }
            else if(p->is_tcp())
                js.put("proto", "TCP");
            else if(p->is_udp())
                js.put("proto", "UDP");
            else if(p->is_icmp())
                js.put("proto", "ICMP");
                
            bool found = false;

            //client
            for (auto& it : default_ips)
            {
                string name = it.first;
                std::vector<const snort::SfCidr*> ip_addresses = it.second;
                for (auto& ip : ip_addresses)
                {
                    int comp = ip->contains(&cli_ip);
                    if(comp == SFIP_CONTAINS and name!="EXTERNAL_NET")
                    {
                        js.put("src", name);
                        found = true;
                    }
                }
            }
            if(!found)
            {
                if(asn_client>0)
                {
                    js.put("src", to_string(asn_client));
                }
                else
                {
                    js.put("src", cli_ip_str);
                }
            }
            //server
            found = false;
            for (auto& it : default_ips)
            {
                string name = it.first;
                std::vector<const snort::SfCidr*> ip_addresses = it.second;
                for (auto& ip : ip_addresses)
                {
                    int comp = ip->contains(&srv_ip);
                    if(comp == SFIP_CONTAINS and name!="EXTERNAL_NET")
                    {
                        js.put("dst", name);
                        found = true;
                    }
                }
            }
            if(!found)
            {
                if(asn_server>0)
                {
                    js.put("dst", to_string(asn_server));
                }
                else
                {
                    js.put("dst", srv_ip_str);
                }
            }
            js.close();
            std::ofstream file_stream;
            file_stream.open("alert_dos_json.txt", std::ios_base::app);

            if (file_stream.is_open()) {
                file_stream << ss.str();
                file_stream.close();
            }
            else {
                WarningMessage("%s\n", "Error opening file");
            }
        }
    }
}



//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new DoSJsonModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* dos_json_ctor(Module* mod)
{ return new DoSJsonLogger((DoSJsonModule*)mod); }

static void dos_json_dtor(Logger* p)
{ delete p; }

static LogApi dos_json_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    dos_json_ctor,
    dos_json_dtor
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &dos_json_api.base,
    nullptr
};

