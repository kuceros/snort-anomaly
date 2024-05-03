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
// interval_detector.cc author Rostislav Kucera <kucera.rosta@gmail.com>, 2024
// based on appid_listener.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef INTERVAL_DETECTOR_H
#define INTERVAL_DETECTOR_H

#include <fstream>
#include <mutex>
#include <string>
#include <maxminddb.h>

#include "main/snort_config.h"
#include "main/snort_types.h"
#include "libml.h"

#include "main/snort_types.h"

#define MOD_NAME "interval_detector"
#define INTERVAL_DETECTOR_GID 666
#define INTERVAL_DETECTOR_INTERVAL 1
#define INTERVAL_DETECTOR_FROM 2
#define INTERVAL_DETECTOR_TO 3

struct IntervalDetectorConfig
{
    bool training = false;
    std::string file_name;
    std::string model;
    bool load_model = false;
    std::string db_name;
    std::ofstream file_stream;
    std::mutex file_mutex;
    int window = 600;
    int interval = 60;
    int num_sigma = 12;
    std::map<std::string, std::vector<const snort::SfCidr*>> default_ips;
    BinaryClassifier classifier;
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




#endif