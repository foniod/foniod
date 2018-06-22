FROM rust

RUN echo "deb http://httpredir.debian.org/debian/ stable main non-free" >> /etc/apt/sources.list \
    && echo "deb-src http://httpredir.debian.org/debian/ stable main non-free" >> /etc/apt/sources.list \
    && echo "deb http://security.debian.org/ stable/updates stable non-free" >> /etc/apt/sources.list \
    && apt-get update \
    && apt-get -y install debhelper cmake libllvm3.8 llvm-3.8-dev libclang-3.8-dev \
       libelf-dev bison flex libedit-dev clang-format-3.8 python python-netaddr \
       python-pyroute2 luajit libluajit-5.1-dev arping iperf netperf ethtool \
       devscripts zlib1g-dev libfl-dev 

WORKDIR /tmp
RUN git clone https://github.com/iovisor/bcc.git \
    && cd bcc; mkdir build; cd build \
    && cmake -DCMAKE_INSTALL_PREFIX=/usr .. \
    && make \
    && make install

WORKDIR /build
