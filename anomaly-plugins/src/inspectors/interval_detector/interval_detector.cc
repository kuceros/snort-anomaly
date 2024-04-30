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
// appid_listener.cc author Rajeshwari Adapalam <rajadapa@cisco.com>

#include "interval_detector.h"

#include <ctime>

#include <maxminddb.h>

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
//#include "sfip/sf_ipvar.h"

#include "interval_detector_event_handler.h"

using namespace snort;

static const char* s_help = "log selected published data to interval_detector.log";

static const Parameter s_params[] =
{
    { "json_logging", Parameter::PT_BOOL, nullptr, "false",
        "log appid data in json format" },
    { "file", Parameter::PT_STRING, nullptr, nullptr,
        "output data to given file" },
    { "training", Parameter::PT_BOOL, nullptr, nullptr,
        "training detection model" },
    { "training_time", Parameter::PT_INT, nullptr, nullptr,
        "training time" },
    { "model", Parameter::PT_STRING, nullptr, nullptr,
        "input detection model" },
    { "load_model", Parameter::PT_BOOL, nullptr, nullptr,
        "load detection model" },
    { "db", Parameter::PT_STRING, nullptr, nullptr,
        "input GeoLite2 ASN database" },
    { "win_size", Parameter::PT_INT, nullptr, nullptr, 
        "size of training window" },
    { "interval_size", Parameter::PT_INT, nullptr, nullptr, 
        "size of detection interval" },
    { "num_sigma", Parameter::PT_INT, nullptr, nullptr, 
        "number of sigmas as a threshold" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static RuleMap inter_rules[] =
{
    { INTERVAL_DETECTOR_INTERVAL, "interval begins" },
    { INTERVAL_DETECTOR_FROM, "attack from" },
    { INTERVAL_DETECTOR_TO, "attack to" },
    { 0, nullptr }
};

class IntervalDetectorModule : public Module
{
public:

    IntervalDetectorModule() : Module(MOD_NAME, s_help, s_params) { }

    ~IntervalDetectorModule() override
    {
        delete config;
    }

    bool begin(const char*, int, SnortConfig*) override
    {
        if ( config )
            return false;

        config = new IntervalDetectorConfig;
        return true;
    }

    bool set(const char*, Value& v, SnortConfig*) override
    {
        if ( v.is("json_logging") )
            config->json_logging = v.get_bool();
        else if ( v.is("file") )
            config->file_name = v.get_string();
        else if ( v.is("training") )
            config->training = v.get_bool();
        else if ( v.is("load_model") )
            config->load_model = v.get_bool();
        else if ( v.is("training_time") )
        {
            if(config->training)
                config->window = v.get_uint32();
        }
        else if (v.is("model") )
            config->model = v.get_string();
        else if ( v.is("db") )
            config->db_name = v.get_string();
        else if ( v.is("win_size") )
            config->window= v.get_uint32();
        else if ( v.is("interval_size") )
            config->interval = v.get_uint32();
        else if ( v.is("num_sigma") )
            config->num_sigma = v.get_uint32();

        return true;
    }
    unsigned get_gid() const override
    { return INTERVAL_DETECTOR_GID; }

    const RuleMap* get_rules() const override
    {
        return inter_rules; 
    }

    IntervalDetectorConfig* get_data()
    {
        IntervalDetectorConfig* temp = config;
        config = nullptr;
        return temp;
    }

private:
    IntervalDetectorConfig* config = nullptr;
};

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------


class IntervalDetectorInspector : public Inspector
{
public:
    IntervalDetectorInspector(IntervalDetectorModule& mod)
    {
        config = mod.get_data();
        assert(config);
    }

    ~IntervalDetectorInspector() override
    {
        delete config; }

    void eval(Packet*) override { }

    bool configure(SnortConfig* sc) override
    {
        assert(config);
        if(config->training and config->load_model)
        {
            WarningMessage("interval_detector: error config both training and load model\n");
            return false;
        }
        sc->set_run_flags(RUN_FLAG__TRACK_ON_SYN);
        if (!config->file_name.empty())
        {
            config->file_stream.open(config->file_name, std::ios::app);
            if (!config->file_stream.is_open())
                WarningMessage("interval_detector: can't open file %s\n", config->file_name.c_str());
        }

        sfip_var_t* it_var = get_ips_policy()->ip_vartable->head;

        while (it_var)
        {
            std::vector<const snort::SfCidr*> ip_addresses;
            std::string name = it_var->name;
            _ip_node* it_node = it_var->head;
            while (it_node)
            {
                const snort::SfCidr* ip = it_node->ip;
                ip_addresses.push_back(ip);
                it_node = it_node->next;
            }
            config->default_ips[name] = ip_addresses;
            it_var = it_var->next;
        }
        DataBus::subscribe_network(appid_pub_key, AppIdEventIds::ANY_CHANGE, new IntervalDetectorEventHandler(*config));

        return true;
    }
    

private:
    IntervalDetectorConfig* config = nullptr;
};

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new IntervalDetectorModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static Inspector* ad_ctor(Module* m)
{
    assert(m);
    return new IntervalDetectorInspector((IntervalDetectorModule&)*m);
}

static void ad_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi inter_detect_api
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
    &inter_detect_api.base,
    nullptr
};

