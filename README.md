# ENFTUN - Xaptum ENF Tunnel Client

`enftun` is a tunnel client for connecting to the Xaptum Edge Network Fabric (ENF).

## Installation from Source

### Build Dependencies

* CMake (version 3.0 or higher)
* A C99-compliant compiler

* [OpenSSL]() (version 1.1.0 or higher)

### Building the Binary

``` bash
# Create a subdirectory to hold the build
mkdir -p build
cd build

# Configure the build
cmake .. -CMAKE_BUILD_TYPE=RelWithDebInfo

# Build the library
cmake --build .
```

### CMake Options

The following CMake configuration options are supported.

| Option               | Values         | Default    | Description                                |
|----------------------|----------------|------------|--------------------------------------------|
| CMAKE_BUILD_TYPE     | Release        |            | With full optimizations.                   |
|                      | Debug          |            | With debug symbols.                        |
|                      | RelWithDebInfo |            | With full optimizations and debug symbols. |
| CMAKE_INSTALL_PREFIX | <string>       | /usr/local | The directory to install the library in.   |

## Usage

### Preparing the TUN device

The TUN device must be created prior to starting `enftun`.

A [`systemd`]() unit file to managed TUN devices is located in this repo.  Copy the `systemd/tun@.service` file to `/etc/systemd/service/` and run `systemctl start tun@enf0.service`.

Or use the following `iproute2` commands.
``` bash
ip tuntap add mode tun enf0
ip link set dev enf0 mtu 1280
ip link set dev enf0 up
```

### Configuring enftun

An example configuration file is located in `example/example.conf`.  See documentation in the example file for more information.

### Running enftun

``` bash
enftun -c <path_to_config_file>
```

### Adding a route and IP address

Add the IP address specified in the config file to the tunnel interface:

``` bash
ip addr add dev enf0 <ipv6_address>
```

Direct all IPv6 traffic through the tunnel interface:

``` bash
ip -6 route add default dev enf0
```

## Development

An example server is available for testing and development.  It
responds to ICMPv6 echo requests from the client, so `ping -6 ...` can
be used from the client to test the connection.

To start the server run:
``` bash
cd test
python3 router.py
```

In a separate terminal, run the tunnel.

``` bash
cd build

./enftun -c conf/example.conf
```

# License
Copyright 2018 Xaptum, Inc.

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this work except in compliance with the License. You may obtain a copy of
the License from the LICENSE.txt file or at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
