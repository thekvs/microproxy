package main

import (
	"github.com/sigu-399/gojsonschema"

	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
)

type configuration struct {
	Listen              string            `json:"listen"`
	AccessLog           string            `json:"access_log"`
	ActivityLog         string            `json:"activity_log"`
	AllowedConnectPorts []int             `json:"allowed_connect_ports"`
	AllowedNetworks     []string          `json:"allowed_networks"`
	DisallowedNetworks  []string          `json:"disallowed_networks"`
	AuthRealm           string            `json:"auth_realm"`
	AuthType            string            `json:"auth_type"`
	AuthFile            string            `json:"auth_file"`
	ForwardedForHeader  string            `json:"forwarded_for_header"`
	BindIP              string            `json:"bind_ip"`
	ViaHeader           string            `json:"via_header"`
	ViaProxyName        string            `json:"via_proxy_name"`
	AddHeaders          map[string]string `json:"add_headers"`
}

const (
	defaultListenAddress      = "127.0.0.1:3128"
	defaultAllowedNetwork     = "127.0.0.1/32"
	defaultAllowedConnectPort = 443
)

func validateConfigurationFileSchema(fileName string) {
	var document interface{}
	err := json.Unmarshal([]byte(validationSchema), &document)
	if err != nil {
		log.Fatalf("Couldn't parse JSON schema: %v", err)
	}

	schema, err := gojsonschema.NewJsonSchemaDocument(document)
	if err != nil {
		log.Fatalf("Error while loading schema: %v\n", err)
	}

	data, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("Couldn't open configuration file: %v", err)
	}

	buffer, err := ioutil.ReadAll(data)
	if err != nil {
		log.Fatalf("Couldn't read configuration file: %v\n", err)
	}

	var config interface{}
	err = json.Unmarshal(buffer, &config)
	if err != nil {
		log.Fatalf("Couldn't parse configuration file: %v\n", err)
	}

	result := schema.Validate(config)
	if !result.Valid() {
		fmt.Println("Configuration file is not valid:")
		// Loop through errors
		for _, desc := range result.Errors() {
			fmt.Printf(" %s\n", desc)
		}
		os.Exit(1)
	}
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

func validateIP(addr string) {
	ip := net.ParseIP(addr)
	if ip == nil {
		log.Fatalf("incorrect IP address %s", addr)
	}
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
		conf.Listen = defaultListenAddress
	}

	// if no auth. enabled allow only from 127.0.0.1/32 if not deliberatly specified otherwise
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

	return conf
}

const validationSchema = `
{
    "type": "object",
    "properties": {
        "listen": {
            "type": "string"
        },
        "bind_ip": {
            "type": "string"
        },
        "access_log": {
            "type": "string"
        },
        "activity_log": {
            "type": "string"
        },
        "auth_file": {
            "type": "string"
        },
        "auth_type": {
            "type": "string",
            "enum": [
                "basic",
                "digest"
            ]
        },
        "auth_realm": {
            "type": "string"
        },
        "forwarded_for_header": {
            "type": "string",
            "enum": [
                "on",
                "off",
                "delete",
                "truncate"
            ]
        },
        "via_header": {
            "type": "string",
            "enum": [
                "on",
                "off",
                "delete"
            ]
        },
        "via_proxy_name": {
            "type": "string"
        },
        "allowed_networks": {
            "items": {
                "type": "string"
            }
        },
        "disallowed_networks": {
            "items": {
                "type": "string"
            }
        },
        "allowed_connect_ports": {
            "items": {
                "type": "integer",
                "maximum": 65535,
                "minimum": 1
            }
        },
        "add_headers": {
            "type": "object",
            "patternProperties": {
                "^*": {
                    "type": "string"
                }
            }
        }
    },
    "additionalProperties": false
}

`
