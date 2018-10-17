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
cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo

# Build the library
cmake --build .

# Install the libary
cmake --build . --target install
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

### Using Systemd

A [`systemd`]() unit file to manage an enftun are included in this
repo.

First copy the `example/example.conf` configuration file to
`/etc/enftun/enf0.conf` and make any desired changes.

Then enable or start the `enftun` services.

``` bash
# Enable enf0 to start on boot
systemctl enable enftun-setup@enf0
systemctl enable enftun@enf0

# Start enf0 manually
systemctl start enftun@enf0
```

### Manual usage

An example configuration file is located in `example/example.conf`.
See documentation in the example file for more information.

##### enftun-setup
The TUN device should be created must be created prior to starting
`enftun`.

Additionally, any desired routes should be configured before other
networking services start. This will ensure that traffic intended for
the ENF cannot transit a different interface before the enftun is
configured.

The `enftun-setup` script included in this package will perform this
setup.

``` bash
enftun-setup up <path_to_config_file>
```

#### enftun

After `enftun-setup` is complete, run the `enftun`.

``` bash
enftun -c <path_to_config_file>
```

## Development

An example server is available for testing and development.  It
responds to ICMPv6 echo requests from the client, so `ping -6 ...` can
be used from the client to test the connection.

Python3 and the dependencies listed in `test/requirements.txt` must be
installed.

To start the server run:
``` bash
$ cd test
$ python3 router.py
```

In a separate terminal, run the tunnel.

``` bash
$ cd build

$ ./enftun -c conf/example.conf
```

### Virtual Environment

The required Python3 dependencies can be installed in a local virtual
environment rather than in the global system directories.

``` bash
$ cd test

# Create a virtual environment for python
$ python3 -m venv enftun-env
$ source enftun-env/bin/activate

# Install the dependencies
(enftun-env) $ pip3 install -r requirements.txt

# Run the router
(enftun-env) $ python3 router.py
```

The manifest file `requirements.txt` contains a list of all necessary,
non-standard modules required by router.py. The preferred installation
procedure is `pip install -r requirements.txt`.

Note that router.py is not compatible with Python 2. On Debian, or it's
derivatives, the `pip` command will install modules for Python 2, and you
may have to use `pip3` instead to update your Python 3 environment.

If you prefer to not install extra modules globally, it is possible
to use a virtual environment to install these extra modules:

``` bash
$ sudo apt install python3-venv
$ python3 -m venv enftun-env
$ source enftun-env/bin/activate
(enftun-env) $ python -V
Python 3.6.6
(enftun-env) $ pip install -r requirements.txt
(enftun-env) $ python router.py
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
