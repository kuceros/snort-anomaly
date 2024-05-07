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
// flow_ml.cc author Rostislav Kucera <kucera.rosta@gmail.com>, 2024
// based on appid_listener.cc author Rajeshwari Adapalam <rajadapa@cisco.com>

#include "flow_ml.h"

#include <ctime>

#include "framework/decode_data.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "main/snort_config.h"
#include "main/snort_types.h"
#include "profiler/profiler.h"
#include "pub_sub/appid_event_ids.h"
#include "pub_sub/http_events.h"
#include "pub_sub/stream_event_ids.h"
#include "time/packet_time.h"
#include "events/event.h"
#include "libml.h"

#include "pub_sub/intrinsic_event_ids.h"

#include "detection/signature.h"

#include "flow_ml_event_handler.h"

using namespace snort;

static const char* s_help = "log selected published data to interval_detector.log";

static const Parameter s_params[] =
{
    { "model", Parameter::PT_STRING, nullptr, nullptr,
        "input detection model" },
    { "scaler_file", Parameter::PT_STRING, nullptr, nullptr,
        "scaler info for data normalization" },
    { "threshold", Parameter::PT_REAL, nullptr, nullptr,
        "output threshold for detection" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static RuleMap inter_rules[] =
{
    { FLOW_ML_ATTACK, "DoS attack" },
    { 0, nullptr }
};

class FlowMLModule : public Module
{
public:

    FlowMLModule() : Module(MOD_NAME, s_help, s_params) { }

    ~FlowMLModule() override
    {
        delete config;
    }

    bool begin(const char*, int, SnortConfig*) override
    {
        if ( config )
            return false;

        config = new FlowMLConfig;
        return true;
    }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        if (v.is("model") )
            config->model = v.get_string();
        else if (v.is("threshold") )
            config->threshold = v.get_real();
        else if (v.is("scaler_file") )
            config->scaler_file = v.get_string();
        return true;
    }
    unsigned get_gid() const override
    { return FLOW_ML_GID; }

    const RuleMap* get_rules() const override
    {
        return inter_rules; 
    }

    FlowMLConfig* get_data()
    {
        FlowMLConfig* temp = config;
        config = nullptr;
        return temp;
    }

private:
    FlowMLConfig* config = nullptr;
};

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------


class FlowMLInspector : public Inspector
{
public:
    FlowMLInspector(FlowMLModule& mod)
    {
        config = mod.get_data();
        assert(config);
    }

    ~FlowMLInspector() override
    {
        delete config; }

    void eval(Packet*) override { }

        /**
     * @brief Loads scaler information from a file.
     * 
     * This function reads scaler information from a file with the given filename. The details of the scaler information and the file format are not provided in the code snippet.
     * 
     * @param filename The name of the file from which the scaler information will be loaded.
     * @return ScalerInfo The loaded scaler information.
     */
    ScalerInfo loadScalerInfo(const std::string& filename) {
        ScalerInfo scaler_info;

        std::ifstream file(filename, std::ios::binary);
        if (!file) {
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


    bool configure(SnortConfig* sc) override
    {
        assert(config);
        sc->set_run_flags(RUN_FLAG__TRACK_ON_SYN);

        if (!config->classifier.buildFlowModel(config->model)) {
            WarningMessage("Failed to build model.\n");
            return false;
        }
    
        config->scaler_info = loadScalerInfo(config->scaler_file);
        if(config->scaler_info.min_values.empty() or config->scaler_info.max_values.empty()){
            WarningMessage("Failed to load scaler file.\n");
            return false;
        }
        DataBus::subscribe_network(appid_pub_key, AppIdEventIds::ANY_CHANGE, new FlowMLEventHandler(*config));

        return true;
    }
    

private:
    FlowMLConfig* config = nullptr;
};

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FlowMLModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Inspector* ad_ctor(Module* m)
{
    assert(m);
    return new FlowMLInspector((FlowMLModule&)*m);
}

static void ad_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi flow_ml_api
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        MOD_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__NONE,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit,
    nullptr, // tterm,
    ad_ctor,
    ad_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &flow_ml_api.base,
    nullptr
};

