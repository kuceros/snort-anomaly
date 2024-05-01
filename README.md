# Snort anomaly plugins
## Installation
1. Download this repository and extract it.
2. Download *libml* library from GitHub.com (https://github.com/snort3/libml) and extract it.
3. Replace source files "libml.cc" and "libml.h" in "limbl/src" folder with files with the same name from this repository.
4. Install this library: 
<pre>
    ./configure.sh
    cd build
    sudo make -j$(nproc) install
</pre>
5. Go to extracted *anomaly-detection* repository.
6. Install *anomaly-plugins*:
<pre>
    cd anomaly-plugins
    sudo ./configure_cmake.sh
    cd build
    sudo make install
</pre>

## Training FlowML model
1. Run Snort 3 with *interval_detector* enabled, in which "label_logging" is enabled.
2. Run `./create_data.sh "<your_path>/datasets"` which creates labeled flow data from input dataset for training ML model.
3. Run `python3 train_snort.py`
4. Output files can be used in FlowML module and set as an input as in the example configuration below...


### Snort configuration example (snort.lua)
    interval_detector =
    {
        file = 'data_labeled.csv', --output file with labeled data
        training = false, --training thresholds
        load_model = true, --load pretrained thresholds
        training_time = 20000, --training time in seconds
        model = '<your_path>/interval.model', --pretrained model with thresholds
        db = '<your_path>/GeoLite2-ASN/GeoLite2-ASN.mmdb', --ASN database
        win_size = 300, --training window if model not loaded
        interval_size = 30, --detection interval if model not loaded
        num_sigma = 12, --multiple sigma as a threshold
    }

    flow_ml =
    {
        model = '<your_path>/Desktop/snort.model', --load ML model
        threshold = 0.99, --classification threshold
        scaler_file = '<your_path>/scaler_info.bin', --file with data for incoming data normalization
    }

    alert_dos_json = { 
        file = true, --logging to file
        flow_ml = true, --logging FlowML alerts
        interval = true, --logging interval detector alerts
        mapping = "<your_path>/rules_parsed.csv", --rule-Mitre mapping file
        db = '<your_path>/GeoLite2-ASN/GeoLite2-ASN.mmdb' --ASN database
    }




