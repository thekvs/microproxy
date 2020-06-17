package main

import (
	"io"
	"log"
	"net"
	"os"

	"github.com/BurntSushi/toml"
)

type Configuration struct {
	Listen              string     `toml:"listen"`
	AccessLog           string     `toml:"access_log"`
	ActivityLog         string     `toml:"activity_log"`
	AllowedConnectPorts []int      `toml:"allowed_connect_ports"`
	AllowedNetworks     []string   `toml:"allowed_networks"`
	DisallowedNetworks  []string   `toml:"disallowed_networks"`
	AuthRealm           string     `toml:"auth_realm"`
	AuthType            string     `toml:"auth_type"`
	AuthFile            string     `toml:"auth_file"`
	ForwardedForHeader  string     `toml:"forwarded_for_header"`
	BindIP              string     `toml:"bind_ip"`
	ViaHeader           string     `toml:"via_header"`
	ViaProxyName        string     `toml:"via_proxy_name"`
	AddHeaders          [][]string `toml:"add_headers"`
	ForwardProxyURL     string     `toml:"forward_proxy_url"`
}

const (
	defaultListenAddress      = "127.0.0.1:3128"
	defaultAllowedNetwork     = "127.0.0.1/32"
	defaultAllowedConnectPort = 443
)

func validateNetworks(networks []string) {
	if len(networks) > 0 {
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

func validateIP(addr string) {
	if addr != "" {
		ip := net.ParseIP(addr)
		if ip == nil {
			log.Fatalf("incorrect IP address %s", addr)
		}
	}
}

func validateAuthType(authType string) {
	validValues := map[string]bool{
		"":       true,
		"basic":  true,
		"digest": true,
	}

	_, ok := validValues[authType]
	if !ok {
		log.Fatalf("Incorrect authentication type '%s'", authType)
	}
}

func validateForwardedForHeaderAction(action string) {
	validValues := map[string]bool{
		"on":       true,
		"off":      true,
		"delete":   true,
		"truncate": true,
	}

	_, ok := validValues[action]
	if !ok {
		log.Fatalf("Incorrect 'Forwarded-For' header action '%s'", action)
	}
}

func validateViaHeaderAction(action string) {
	validValues := map[string]bool{
		"on":     true,
		"off":    true,
		"delete": true,
	}

	_, ok := validValues[action]
	if !ok {
		log.Fatalf("Incorrect 'Via' header action '%s'", action)
	}
}

func newConfigurationFromFile(path string) *Configuration {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal("can't open configuration file: ", err)
	}

	conf := newConfiguration(file)

	return conf
}

func newConfiguration(data io.Reader) *Configuration {
	var conf Configuration
	if _, err := toml.DecodeReader(data, &conf); err != nil {
		log.Fatalf("Couldn't parse configuration file: %v", err)
	}

	if conf.Listen == "" {
		conf.Listen = defaultListenAddress
	}

	// if no auth. enabled allow only from 127.0.0.1/32 if not deliberately specified otherwise
	if conf.AllowedNetworks == nil || len(conf.AllowedNetworks) == 0 {
		if conf.AuthFile == "" || conf.AuthType == "" {
			conf.AllowedNetworks = make([]string, 1)
			conf.AllowedNetworks[0] = defaultAllowedNetwork
		}
	}

	validateNetworks(conf.AllowedNetworks)
	validateNetworks(conf.DisallowedNetworks)
	validateIP(conf.BindIP)

	// by default allow connect only to the https protocol port
	if conf.AllowedConnectPorts == nil || len(conf.AllowedConnectPorts) == 0 {
		conf.AllowedConnectPorts = make([]int, 1)
		conf.AllowedConnectPorts[0] = defaultAllowedConnectPort
	}

	if conf.AuthType == "" && conf.AuthFile != "" {
		log.Fatal("missed mandatoty configuration parameter 'auth_type'")
	}

	// by default set X-Forwarded-For header
	if conf.ForwardedForHeader == "" {
		conf.ForwardedForHeader = "on"
	}

	if conf.ViaHeader == "" {
		conf.ViaHeader = "on"
	}

	if conf.ViaProxyName == "" && conf.ViaHeader == "on" {
		hostname, err := os.Hostname()
		if err != nil {
			log.Fatalf("os.Hostname() failed: %v\n", err)
		}
		conf.ViaProxyName = hostname
	}

	validateAuthType(conf.AuthType)
	validateForwardedForHeaderAction(conf.ForwardedForHeader)
	validateViaHeaderAction(conf.ViaHeader)

	return &conf
}
