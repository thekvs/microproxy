package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
)

type Configuration struct {
	Listen              string
	AccessLog           string
	ActivityLog         string
	AllowedConnectPorts []string
	AllowedNetworks     []string
	DisallowedNetworks  []string
	AuthRealm           string
	AuthType            string
	AuthFile            string
	ForwardedFor        string
	BindIP              string
}

func validateNetworks(networks []string) {
	if networks != nil && len(networks) > 0 {
		for i, network := range networks {
			_, _, err := net.ParseCIDR(network)
			if err != nil {
				if ip := net.ParseIP(network); ip != nil {
					if ip4 := ip.To4(); ip4 != nil {
						networks[i] = network + "/32"
						continue
					}
					if ip16 := ip.To16(); ip16 != nil {
						networks[i] = network + "/128"
						continue
					}
				}
				log.Fatalf("couldn't parse network %s: %v", network, err)
			}
		}
	}
}

func NewConfiguration(path string) *Configuration {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal("can't open configuration file: ", err)
	}

	decoder := json.NewDecoder(file)
	conf := &Configuration{}
	decoder.Decode(&conf)

	if conf.Listen == "" {
		conf.Listen = "127.0.0.1:3128"
	}

	// if no auth. enabled allow only from 127.0.0.1/32 if not deliberatly specified otherwise
	if conf.AllowedNetworks == nil || len(conf.AllowedNetworks) == 0 {
		if conf.AuthFile == "" || conf.AuthType == "" {
			conf.AllowedNetworks = make([]string, 1)
			conf.AllowedNetworks[0] = "127.0.0.1/32"
		}
	}

	validateNetworks(conf.AllowedNetworks)
	validateNetworks(conf.DisallowedNetworks)

	// by default allow connect only to the https protocol port
	if conf.AllowedConnectPorts == nil || len(conf.AllowedConnectPorts) == 0 {
		conf.AllowedConnectPorts = make([]string, 1)
		conf.AllowedConnectPorts[0] = "443"
	}

	if conf.AuthType == "" && conf.AuthFile != "" {
		log.Fatal("missed mandatoty configuration parameter \"AuthType\"")
	}

	if conf.AuthType != "basic" && conf.AuthType != "digest" && conf.AuthType != "" {
		log.Fatalf("unexpected value \"%v\" for AuthType parameter", conf.AuthType)
	}

	// by default set X-Forwarded-For header
	if conf.ForwardedFor == "" {
		conf.ForwardedFor = "on"
	}

	allowedForwardedForValues := map[string]bool{"off": true, "on": true, "delete": true, "truncate": true}
	_, found := allowedForwardedForValues[conf.ForwardedFor]
	if !found {
		log.Fatalf("unexpected value \"%v\" for ForwardedFor parameter", conf.ForwardedFor)
	}

	return conf
}
