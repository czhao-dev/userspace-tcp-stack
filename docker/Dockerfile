FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    g++ \
    gdb \
    cmake \
    ninja-build \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    curl \
    tcpdump \
    net-tools \
    sudo \
    less \
    vim \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /minitcp

CMD ["/bin/bash"]
