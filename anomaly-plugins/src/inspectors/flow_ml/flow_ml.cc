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

    /**
     * @brief Constructor for the FlowMLModule class.
     * 
     * This constructor initializes the FlowMLModule with the name, help text, 
     * and parameters defined in the constants MOD_NAME, s_help, and s_params, respectively.
     */
    FlowMLModule() : Module(MOD_NAME, s_help, s_params) { }

    /**
     * @brief Destructor for the FlowMLModule class.
     * 
     * This destructor deletes the config object if it exists.
     */
    ~FlowMLModule() override
    {
        delete config;
    }

    /**
     * @brief Begins the configuration process for the FlowMLModule.
     * 
     * This function checks if the config object exists. 
     * If it does, the function returns false, indicating that the configuration process cannot begin. 
     * If the config object does not exist, the function creates a new FlowMLConfig object, 
     * assigns it to the config pointer, and returns true, indicating that the configuration process can begin.
     * 
     * @param char* Unused parameter.
     * @param int Unused parameter.
     * @param SnortConfig* Unused parameter.
     * @return bool True if the configuration process can begin, false otherwise.
     */
    bool begin(const char*, int, SnortConfig*) override
    {
        if ( config )
            return false;

        config = new FlowMLConfig;
        return true;
    }

    /**
     * @brief Sets the configuration values based on the provided value.
     * 
     * This function checks the name of the provided value and sets the corresponding configuration value based on it. 
     * If the name is "model", it sets the model configuration value. If the name is "threshold", it sets the threshold configuration value.
     * 
     * @param char* Unused parameter.
     * @param Value& v The value to set.
     * @param SnortConfig* Unused parameter.
     * @return bool Always returns true.
     */
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
    /**
     * @brief Returns the group identifier for the FlowMLModule.
     * 
     * This function returns the group identifier for the FlowMLModule, which is FLOW_ML_GID.
     * 
     * @return unsigned The group identifier for the FlowMLModule.
     */
    unsigned get_gid() const override
    { return FLOW_ML_GID; }

    /**
     * @brief Returns the rules for the FlowMLModule.
     * 
     * This function returns the rules for the FlowMLModule, which are defined in the flow_ml_rules array.
     * 
     * @return const RuleMap* The rules for the FlowMLModule.
     */
    const RuleMap* get_rules() const override
    {
        return inter_rules; 
    }

    /**
     * @brief Returns the configuration data for the FlowMLModule.
     * 
     * This function returns the configuration data for the FlowMLModule and sets the config pointer to null.
     * 
     * @return FlowMLConfig* The configuration data for the FlowMLModule.
     */
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

    /**
     * @brief Constructor for the FlowMLInspector class.
     * 
     * This constructor initializes the FlowMLInspector with the data from the provided FlowMLModule. 
     * It asserts that the config is not null.
     * 
     * @param FlowMLModule& mod The module from which to get the data.
     */
    FlowMLInspector(FlowMLModule& mod)
    {
        config = mod.get_data();
        assert(config);
    }

    /**
     * @brief Destructor for the FlowMLInspector class.
     * 
     * This destructor deletes the config object if it exists.
     */
    ~FlowMLInspector() override
    {
        delete config; }

    void eval(Packet*) override { }

    /**
     * @brief Loads scaler information from a file.
     * 
     * This function reads scaler information from a file with the given filename. 
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

    /**
     * @brief Configures the SnortConfig object.
     * 
     * This function asserts that the config is not null, sets the run flags on the SnortConfig object, and attempts to build the flow model. 
     * If the flow model cannot be built, it prints a warning message and returns false. 
     * It then loads the scaler information from the scaler file and checks if the min_values and max_values are empty. 
     * If they are, it prints a warning message and returns false. Finally, it subscribes to the network data bus and returns true.
     * 
     * @param sc The SnortConfig object to configure.
     * @return bool True if the configuration was successful, false otherwise.
     */
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

