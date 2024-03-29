## About
`microproxy` is a lightweight non-caching HTTP/HTTPS proxy server.

## Main features
* Single executable with no external dependencies.
* Single simple configuration file in TOML format.
* Basic and Digest access authentication methods.
* IP-based black and white access lists.
* Ability to log all requests.
* Ability to tweak X-Forwarded-For header.
* Ability to specify IP address for outgoing connections.
* Ability to forward requests to upstream proxy.
* Reasonable memory usage.

## Installing
This project is written in the [Go](http://golang.org/) programming language and to build it you need to install Go compiler and set some enviroment variables. [Here is instructions on how to do it](http://golang.org/doc/install). After you've done it, run the following command in your shell:
```
$ go get github.com/thekvs/microproxy
```
and this will build the binary in `$GOPATH/bin`.

Run `go build -mod=vendor` for local build.

## Configuration file options
`microproxy` uses [TOML](https://github.com/toml-lang/toml) format for configuration file. Below is a list of supported configuration options.

* `listen="ip:port"` -- ip address and port where to listen for incoming proxy request. Default: `127.0.0.1:3128`
* `access_log="path"` -- path to a file where to write requested through proxy urls.
* `activity_log="path"` -- path to a file where to write debug and auxiliary information.
* `allowed_connect_ports=[port1, port2, ...]` -- list of allowed port to CONNECT to. Default: `[443]`
* `auth_file="path"` -- path to a file with users' passwords. If you use `digest` auth. scheme this file has to be in the format used by Apache's [htdigest](http://httpd.apache.org/docs/2.4/programs/htdigest.html) utility, for `basic` scheme it has to be in the format used by Apache's [htpasswd](http://httpd.apache.org/docs/2.4/programs/htpasswd.html) utility with -p option, i.e. created as `$ htpasswd -c -p auth.txt username`.
* `auth_type="type"` -- authentication scheme type. Available options are:
  * `"basic"` -- use Basic authentication scheme.
  * `"digest"` -- use Digest authentication scheme.
* `auth_realm="realmstring"` -- realm name which is to be reported to the client for the proxy authentication scheme.
* `forwarded_for_header="action"` -- specifies how to handle `X-Forwarded-For` HTTP protocol header. Available options are:
  * `"on"` -- set `X-Forwarded-For` header with client's IP address, this is a default choice.
  * `"off"` -- do nothing, i.e. leave headear as is.
  * `"delete"` -- delete `X-Forwarded-For` header, this turns on stealth mode.
  * `"truncate"` -- delete all old `X-Forwarded-For` headers and insert a new one with client's IP address.
* `via_header="action"` -- specifies how to handle `Via` HTTP protocol header. Available options are:
  * `"on"` -- set `Via` header, this is a default choice.
  * `"off"` -- do nothing with `Via` header.
  * `"delete"` -- delete `Via` header.
* `via_proxy_name="name"` -- this value will be used as the host name in the `Via` header, by default the server's host name will be used.
* `allowed_networks=["net1", ...]` -- list of whitelisted networks in CIDR format.
* `disallowed_networks=["net1", ...]` -- list of blacklisted networks in CIDR format.
* `bind_ip="ip"` -- specify which IP will be used for outgoing connections.
* `add_headers=[["header1", value1"], ["header2", "value2"]...]` -- adds specified headers to outgoing HTTP requests, this option will not work for HTTPS connections.
* `forward_proxy_url="http://user:password@host:port"` -- specify proxy to forward requests to. Uses basic auth type for the forward proxy.

## Usage

```
$ ./microproxy --config microproxy.toml
```

To enable debug mode, add `-v` switch. To only test configuration file correctness add `-t` switch,
i.e. `$ ./microproxy --config microproxy.toml -t`

## Signal handling
On `USR1` signal microproxy reopens access and activity log files.

## Licensing
All source code included in this distribution is covered by the MIT License found in the LICENSE file.
