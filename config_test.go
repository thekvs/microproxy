package main

import "testing"

func compareSlices(s1 []int, s2 []int) bool {
	if len(s1) == len(s2) {
		for i, v := range s1 {
			if v != s2[i] {
				return false
			}
		}
	} else {
		return false
	}

	return true
}

func TestConfigFile(t *testing.T) {
	expected := configuration{
		Listen:              "127.0.0.1:3129",
		AccessLog:           "/tmp/microproxy.access.log",
		AuthType:            "basic",
		AuthRealm:           "proxy",
		AuthFile:            "auth.txt",
		ForwardedForHeader:  "on",
		AllowedConnectPorts: make([]int, 2)}

	expected.AllowedConnectPorts[0] = 443
	expected.AllowedConnectPorts[1] = 80

	conf := newConfigurationFromFile("microproxy.toml")

	if conf.Listen != expected.Listen {
		t.Errorf("Got %v, expected %v", conf.Listen, expected.Listen)
	}

	if conf.AccessLog != expected.AccessLog {
		t.Errorf("Got %v, expected %v", conf.AccessLog, expected.AccessLog)
	}

	if !compareSlices(conf.AllowedConnectPorts, expected.AllowedConnectPorts) {
		t.Errorf("Got %v, expected %v", conf.AllowedConnectPorts, expected.AllowedConnectPorts)
	}

	if conf.AuthFile != expected.AuthFile {
		t.Errorf("Got %v, expected %v", conf.AuthFile, expected.AuthFile)
	}

	if conf.AuthRealm != expected.AuthRealm {
		t.Errorf("Got %v, expected %v", conf.AuthRealm, expected.AuthRealm)
	}

	if conf.AuthType != expected.AuthType {
		t.Errorf("Got %v, expected %v", conf.AuthType, expected.AuthType)
	}

	if conf.ForwardedForHeader != expected.ForwardedForHeader {
		t.Errorf("Got %v, expected %v", conf.ForwardedForHeader, expected.ForwardedForHeader)
	}
}
