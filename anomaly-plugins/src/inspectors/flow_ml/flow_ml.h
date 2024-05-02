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
// flow_ml.h author Rostislav Kucera <kucera.rosta@gmail.com>, 2024
// appid_listener.h author Shravan Rangaraju <shrarang@cisco.com>

#ifndef FLOW_ML_H
#define FLOW_ML_H

#include <fstream>
#include <mutex>
#include <string>

#include "main/snort_config.h"
#include "main/snort_types.h"
#include "libml.h"

#include "main/snort_types.h"

#define MOD_NAME "flow_ml"
#define FLOW_ML_GID 667
#define FLOW_ML_ATTACK 1

struct FlowMLConfig
{
    std::string model;
    std::string scaler_file;
    float threshold;
    BinaryClassifier classifier;
};

#endif