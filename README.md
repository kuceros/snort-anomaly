# Snort anomaly plugins

This repository contains three plugins for Snort 3: two detection modules, one based on statistical analysis and the other on a neural network; and an output module, which alerts if there is an event from those two detection modules. If the event originates from the statistical module, information about the anomaly interval is also extended with data from the MITRE ATT&CK knowledge base. MaxMind GeoLite2 is utilized for grouping IP addresses.

## Requirements
Install Snort 3:\
&emsp; Snort web: https://www.snort.org/downloads \
&emsp; GitHub source: https://github.com/snort3/snort3

Download MaxMind GeoLite2 ASN binary database:\
&emsp; MaxMind web: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Create CSV Rule-MITRE ATT&CK mapping file with this script:\
&emsp; GitHub source: https://github.com/Resistine/SnortRules

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
5. Install *libmaxminddb* for handling MaxMind ASN database:
    
    Ubuntu:
    ```sudo apt-get install -y libmaxminddb-dev```

    MacOS:
    ```brew install libmaxminddb```
    
    GitHub source:
    https://github.com/maxmind/libmaxminddb

6. Go to extracted *anomaly-detection* repository.
7. Install *anomaly-plugins*:
<pre>
    cd anomaly-plugins
    sudo ./configure_cmake.sh
    cd build
    sudo make install
</pre>

## Training FlowML model
1. Run Snort 3 with *interval_detector* enabled, in which "file_labels" with file path is enabled.
2. Run `./create_data.sh "<your_path>/datasets"` which creates labeled flow data from input dataset for training ML model.
3. Run `pip install -r requirements.txt` to install required Python libraries.
3. Run `python3 train_snort.py "<your_csv>"` to train a neural network model.
4. Output files can be used in FlowML module and set as an input as in the example configuration below...


### Snort configuration example (snort.lua)
    interval_detector =
    {
        file_labels = 'data_labeled.csv', --output file with labeled data
        training = false, --training thresholds
        load_model = true, --load pretrained thresholds
        training_time = 20100, --training time in seconds
        model = '<your_path>/interval.model', --pretrained model with thresholds
        db = '<your_path>/GeoLite2-ASN/GeoLite2-ASN.mmdb', --ASN database
        win_size = 300, --training window if model not loaded
        interval_size = 30, --detection interval if model not loaded
        num_sigma = 12, --multiple sigma as a threshold
    }

    flow_ml =
    {
        model = '<your_path>/flowml.model', --load ML model
        threshold = 0.99, --classification threshold
        scaler_file = '<your_path>/scaling.bin', --file with data for incoming data normalization
    }

    alert_dos_json = { 
        file = true, --logging to file
        flow_ml = true, --logging FlowML alerts
        interval = true, --logging interval detector alerts
        mapping = "<your_path>/rules_parsed.csv", --rule-Mitre mapping file
        db = '<your_path>/GeoLite2-ASN/GeoLite2-ASN.mmdb' --ASN database
    }

### Example run

```snort -c "<path_to_snort_lua>/snort.lua" -r "<your_input_pcap>" --plugin-path "<path_to_installed_plugins>" -q```


Example path to plugins: ```"/usr/local/snort/lib/snort/plugins/extra/"```

### Creating confusion matrix and SHAP for neural network model:

`python3 confusion_shap.py -d <data_labeled.csv> -s <scaling.bin> -m <flow.model>`


