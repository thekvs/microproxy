[![Build Status](https://travis-ci.org/thekvs/microproxy.svg?branch=master)](https://travis-ci.org/thekvs/microproxy)
## About
```microproxy``` is a minimalistic non-caching HTTP/HTTPS proxy server.

## Main features
* Single executable with no external dependencies.
* Basic and Digest access authentication methods.
* IP-based black and white access lists.
* Ability to log all requests.
* Ability to tweak X-Forwarded-For header.
* Ability to specify ip address for outgoing connections.
* Reasonable memory usage.

## Installing
```
$ go get github.com/thekvs/microproxy
```

## Configuration file options
microproxy uses JSON format for configuration file. Below is a list of supported configuration options.

* ```"Listen": "ip:port"``` -- ip address and port where to listen for incoming proxy request. Default: ```"127.0.0.1:3128"```
* ```"AccessLog": "path"``` -- path to a file where to write requested through proxy urls.
* ```"ActivityLog": "path"``` -- path to a file where to write debug and auxilary information.
* ```"AllowedConnectPorts": ["port1", "port2", ...]``` -- list of allowed port to CONNECT to. Default: ```["443"]```
* ```"AuthFile": "path"``` -- path to a file with users' passwords. If you use "digest" auth. scheme this file has to be in the format used by Apache's htdigest utility, for "basic" scheme it has to be in the format used by Apache's htpasswd utility with -p option, i.e. created as ```$ htpasswd -c -p auth.txt username```.
* ```"AuthType": "type"``` -- authentication scheme type, must be either "basic" or "digest".
* ```"AuthRealm": "realmstring"``` -- realm name which is to be reported to the client for the proxy authentication scheme.
* ```"ForwardedFor": "type"``` -- specifies how to handle X-Forwarded-For HTTP protocol header. Avalible options are: ```"on"``` -- set X-Forwarded-For with client's IP address, ```"off"``` -- do nothing, ```"delete"``` -- delete header, this turns on stealth mode, ```"truncate"``` -- delete all old headers and insert a new one. Default: ```"on"```.
* ```"AllowedNetworks": ["net1", ...]``` -- list of whitelisted networks in CIDR format.
* ```"DisallowedNetworks": ["net1", ...]``` -- list of blacklisted networks in CIDR format.
* ```"BindIP": "ip"``` -- specify which IP will be used for outgoing connections.

## Usage
```
$ ./microproxy --config microproxy.json
```
To enable debug mode, add ```-v``` switch.

This program does not support daemonization, it's better to use other tools like FreeBSD's [daemon](http://www.freebsd.org/cgi/man.cgi?query=daemon&sektion=8) or Linux's [daemonize](http://software.clapper.org/daemonize/).

For example, to run as a user ```proxy``` on FreeBSD you should do:
```
$ sudo daemon -u proxy -p /var/run/microproxy.pid ./microproxy --config microproxy.json
```

## Signal handling
On ```USR1``` signal microproxy reopens access and activity log files.

## Licensing
All source code included in this distribution is covered by the MIT License found in the LICENSE file.
