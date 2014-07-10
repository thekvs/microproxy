package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
)

type configuration struct {
	Listen              string   `json:"listen"`
	AccessLog           string   `json:"access_log"`
	ActivityLog         string   `json:"activity_log"`
	AllowedConnectPorts []string `json:"allowed_connect_ports"`
	AllowedNetworks     []string `json:"allowed_networks"`
	DisallowedNetworks  []string `json:"disallowed_networks"`
	AuthRealm           string   `json:"auth_realm"`
	AuthType            string   `json:"auth_type"`
	AuthFile            string   `json:"auth_file"`
	ForwardedForHeader  string   `json:"forwarded_for_header"`
	BindIP              string   `json:"bind_ip"`
	ViaHeader           string   `json:"via_header"`
	ViaProxyName        string   `json:"via_proxy_name"`
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

func correctChoice(value string, avalibleOptions ...string) bool {
	found := false
	for _, choice := range avalibleOptions {
		if value == choice {
			found = true
			break
		}
	}
	return found
}

func newConfigurationFromFile(path string) *configuration {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal("can't open configuration file: ", err)
	}

	conf := newConfiguration(file)

	return conf
}

func newConfiguration(data io.Reader) *configuration {
	decoder := json.NewDecoder(data)
	conf := &configuration{}
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
	if conf.ForwardedForHeader == "" {
		conf.ForwardedForHeader = "on"
	}

	if !correctChoice(conf.ForwardedForHeader, "off", "on", "delete", "truncate") {
		log.Fatalf("unexpected value \"%v\" for 'forwarded_for_header' configuration parameter", conf.ForwardedForHeader)
	}

	if conf.ViaHeader == "" {
		conf.ViaHeader = "on"
	}

	if !correctChoice(conf.ViaHeader, "on", "off", "delete") {
		log.Fatalf("unexpected value \"%v\" for 'via_header' configuration parameter", conf.ViaHeader)
	}

	if conf.ViaProxyName == "" && conf.ViaHeader == "on" {
		hostname, err := os.Hostname()
		if err != nil {
			log.Fatalf("os.Hostname() failed: %v\n", err)
		}
		conf.ViaProxyName = hostname
	}

	return conf
}
