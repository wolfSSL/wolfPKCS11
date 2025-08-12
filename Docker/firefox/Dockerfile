FROM ubuntu:24.04

ARG WOLFSSL_TAG=v5.8.0-stable
ARG FIREFOX_TAG=78c455227887c316bdde0be2738e31fcecb4547d
# geckodriver should be updated when updating the Firefox version
ARG GECKODRIVER_TAG=v0.36.0

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive
# Set shared library discovery path
ENV LD_LIBRARY_PATH=/usr/local/lib

USER root

# Set timezone to UTC
RUN ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo UTC > /etc/timezone

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    mercurial \
    gyp \
    ninja-build \
    pkg-config \
    zlib1g-dev \
    wget \
    python3 \
    python-is-python3 \
    python3-pip \
    autoconf \
    automake \
    libtool \
    make \
    gdb \
    vim \
    ca-certificates \
    zlib1g-dev \
    gettext \
    llvm \
    alsa \
    libgtk-3-0 \
    libasound2-dev \
    libx11-xcb1 \
    nginx \
    npm \
    python3-selenium \
    ipython3 \
    zip \
    unzip \
    ssh

# Add 'docker' user
ARG USER=docker
ARG UID=1000
ARG GID=1000
RUN groupadd -f -g ${GID} docker && ( getent passwd ${UID} || useradd -ms /bin/bash ${USER} -u ${UID} -g ${GID} )

# Add github.com as an SSH known host
RUN ssh -o StrictHostKeyChecking=no -T git@github.com; cat ~/.ssh/known_hosts >> /etc/ssh/ssh_known_hosts

# Bootstrap and install Firefox dependencies and repository
RUN wget https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/python/mozboot/bin/bootstrap.py
RUN python3 bootstrap.py --no-interactive --application-choice browser

# Clone and build wolfSSL
RUN git clone --depth 1 --branch $WOLFSSL_TAG https://github.com/wolfssl/wolfssl.git
WORKDIR /wolfssl
RUN autoreconf -if
RUN ./configure --enable-all --enable-aescfb --enable-cryptocb --enable-rsapss --enable-keygen \
    --enable-pwdbased --enable-scrypt 'CFLAGS=-DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT'
RUN make && make install
WORKDIR /

# Clone and prepare patch for NSS
RUN git clone https://github.com/LinuxJedi/nss.git
WORKDIR /nss
RUN git diff origin/master origin/wolfPKCS11 > /nss.patch
WORKDIR /

WORKDIR /firefox
RUN git checkout $FIREFOX_TAG
WORKDIR /firefox/security/nss
RUN patch -p1 < /nss.patch
RUN touch /mozconfig
# Enable ASan specific code and build workarounds
#RUN echo ac_add_options --enable-address-sanitizer >> /firefox/mozconfig
# These three are required by ASan
#RUN echo ac_add_options --disable-jemalloc >> /firefox/mozconfig
#RUN echo ac_add_options --disable-crashreporter >> /firefox/mozconfig
#RUN echo ac_add_options --disable-elf-hack >> /firefox/mozconfig
# Keep symbols to symbolize ASan traces later
#RUN echo ac_add_options --disable-install-strip >> /firefox/mozconfig
# Settings for a debug+opt build
#RUN echo ac_add_options --enable-debug >> /firefox/mozconfig
# Make debugging easier
#RUN echo ac_add_options --enable-optimize="-g -O2" >> /firefox/mozconfig
#RUN echo ac_add_options --disable-optimize >> /firefox/mozconfig
ENV MOZCONFIG=/mozconfig
WORKDIR /firefox
RUN ./mach build
WORKDIR /

# Selenium
RUN npm install -g selenium-webdriver
RUN wget https://github.com/mozilla/geckodriver/releases/download/$GECKODRIVER_TAG/geckodriver-$GECKODRIVER_TAG-linux64.tar.gz
RUN tar -xf geckodriver-$GECKODRIVER_TAG-linux64.tar.gz
RUN mv geckodriver /usr/bin/

