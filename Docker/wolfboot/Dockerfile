FROM ubuntu:24.04

ARG WOLFSSL_REF=v5.8.0-stable
ARG WOLFBOOT_REF=master

ENV DEBIAN_FRONTEND=noninteractive
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        git \
        libssl-dev \
        libtool \
        make \
        pkg-config \
        python3 \
        gdb \
    && rm -rf /var/lib/apt/lists/*

# Build and install wolfSSL
RUN git clone --depth 1 --branch ${WOLFSSL_REF} https://github.com/wolfSSL/wolfssl.git /tmp/wolfssl \
    && cd /tmp/wolfssl \
    && ./autogen.sh \
    && ./configure --enable-debug --enable-aescfb --enable-cryptocb --enable-rsapss --enable-keygen \
        --enable-pwdbased --enable-scrypt "C_EXTRA_FLAGS=-DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT -DHAVE_AES_ECB -DHAVE_AES_KEYWRAP" \
    && make -j"$(nproc)" \
    && make install \
    && ldconfig \
    && rm -rf /tmp/wolfssl

# Fetch wolfBoot sources that provide the custom store implementation
RUN git clone --depth 1 --branch ${WOLFBOOT_REF} https://github.com/wolfSSL/wolfBoot.git /opt/wolfBoot

WORKDIR /wolfpkcs11
COPY . /wolfpkcs11

RUN ./autogen.sh \
    && ./configure --enable-debug --with-wolfboot=/opt/wolfBoot CPPFLAGS="-I/usr/local/include" LDFLAGS="-L/usr/local/lib" \
    && make -j"$(nproc)"

#RUN make check
