FROM debian:stretch

RUN apt-get -qq update \
    && apt-get -qq install -y --no-install-recommends \
       build-essential \
       wget \
       clang \
       gcc \
       ca-certificates \
       && rm -rf /var/lib/apt/lists/* \
       && wget -q https://cmake.org/files/v3.11/cmake-3.11.4-Linux-x86_64.tar.gz \
       && tar -xzf cmake-3.11.4-Linux-x86_64.tar.gz \
       && cp -fR cmake-3.11.4-Linux-x86_64/* /usr \
       && rm -rf cmake-3.11.4-Linux-x86_64 \
       && rm cmake-3.11.4-Linux-x86_64.tar.gz

#INSTALL DEPENDENCIES
RUN apt-get update
RUN apt-get install libc6
RUN apt-get install libconfig9
RUN apt-get install -y libconfig-dev
RUN apt-get install libuv1
RUN apt-get install libuv1-dev
RUN apt-get install libssl1.1
RUN apt-get install -y libssl-dev
RUN apt-get -y install gnupg2


RUN apt-key adv --no-tty --keyserver keyserver.ubuntu.com --recv-keys c615bfaa7fe1b4ca
RUN echo "deb http://dl.bintray.com/xaptum/deb stretch main" > /etc/apt/sources.list.d/xaptum.list
RUN apt-get update && apt-get install -y --no-install-recommends apt-utils
RUN apt-get install libsodium18
RUN apt-get install libsodium-dev
RUN apt-get install libamcl4
RUN apt-get install libamcl-dev
RUN apt-get install libxaptum-tpm0
RUN apt-get install libxaptum-tpm-dev
RUN apt-get install libecdaa0
RUN apt-get install libecdaa-dev
RUN apt-get install libecdaa-tpm0
RUN apt-get install libecdaa-tpm-dev
RUN apt-get install libxtt0
RUN apt-get install libxtt-dev
