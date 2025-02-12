package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type confType struct {
	PcapSettings        pcapSettings        `json:"pcapSettings"`
	InfluxV1Settings    influxV1Settings    `json:"influxV1Settings"`
	PerformanceSettings performanceSettings `json:"performanceSettings"`
	FlowFilterSettings  []flowFilter        `json:"flowFilterSettings"`
}

type pcapSettings struct {
	UseRemote         bool   `json:"useRemote"`
	LocalDevice       string `json:"localDevice"`
	LocalMac          string `json:"localMac"`
	RemoteMac         string `json:"remoteMac"`
	SSHUsePubkey      bool   `json:"sshUsePubkey"`
	SSHPubkeyLocation string `json:"sshPubkeyLocation"`
}

type influxV1Settings struct {
	Address    string `json:"address"`
	User       string `json:"user"`
	Password   string `json:"password"`
	Database   string `json:"database"`
	Retention  string `json:"retention"`
	Precision  string `json:"precision"`
	TestDevice string `json:"testDevice"`
}

type performanceSettings struct {
	ErrorRateMapSize      int `json:"errorRateMapSize"`
	PassiveLatencyMapSize int `json:"passiveLatencyMapSize"`
	FlowMapSize           int `json:"flowMapSize"`
	ApplicationMapSize    int `json:"applicationMapSize"`
	FlowMapMaxAgeSeconds  int `json:"flowMapMaxAgeSeconds"`
}

type flowFilter struct {
	FilterName string `json:"filterName"`
	BpfFilter  string `json:"bpfFilter"`
}

var Config confType
var Pcap pcapSettings
var InfluxV1 influxV1Settings
var Performance performanceSettings
var FlowFilterSettings []flowFilter

func ReadJsonConfig() {
	// Open the JSON file
	f, err := os.Open("./config/config.json")
	if err != nil {
		fmt.Println("Error opening config file:", err)
		return
	}
	defer f.Close()

	// Read the file contents
	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Println("Error reading config file:", err)
		return
	}

	// Unmarshal the JSON data into a Config struct
	err = json.Unmarshal(data, &Config)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}
	Pcap = Config.PcapSettings
	InfluxV1 = Config.InfluxV1Settings
	Performance = Config.PerformanceSettings
	FlowFilterSettings = Config.FlowFilterSettings
}
