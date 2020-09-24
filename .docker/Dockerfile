FROM debian:buster

RUN apt-get -qq update \
    && apt-get -qq install -y --no-install-recommends \
       build-essential \
       wget \
       clang \
       gcc \
       ca-certificates \
       && rm -rf /var/lib/apt/lists/*

#INSTALL DEPENDENCIES
RUN apt-get update
RUN apt-get install -y cmake
RUN apt-get install -y libc6
RUN apt-get install -y libconfig9
RUN apt-get install -y libconfig-dev
RUN apt-get install -y libuv1
RUN apt-get install -y libuv1-dev
RUN apt-get install -y libssl1.1
RUN apt-get install -y libssl-dev
RUN apt-get install -y libcurl4-openssl-dev
RUN apt-get install -y libjansson-dev
RUN apt-get install -y gnupg2
RUN apt-get install -y clang-format
RUN apt-get install -y libtss2-dev

RUN apt-key adv --no-tty --keyserver keyserver.ubuntu.com --recv-keys c615bfaa7fe1b4ca
RUN echo "deb http://dl.bintray.com/xaptum/deb buster main" > /etc/apt/sources.list.d/xaptum.list
RUN apt-get update && apt-get install -y --no-install-recommends apt-utils
RUN apt-get install -y libsodium23
RUN apt-get install -y libsodium-dev
RUN apt-get install -y libamcl4
RUN apt-get install -y libamcl-dev
RUN apt-get install -y libxaptum-tpm1
RUN apt-get install -y libxaptum-tpm-dev
RUN apt-get install -y libecdaa1
RUN apt-get install -y libecdaa-dev
RUN apt-get install -y libecdaa-tpm1
RUN apt-get install -y libecdaa-tpm-dev
RUN apt-get install -y libxtt0
RUN apt-get install -y libxtt-dev
