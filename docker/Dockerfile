FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# build-essential is still required even for a pure-Rust build: rustc
# shells out to a system linker (cc/ld) and archiver (ar).
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gdb \
    curl \
    ca-certificates \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    tcpdump \
    net-tools \
    sudo \
    less \
    vim \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --profile default && \
    rustup component add rust-src

WORKDIR /minitcp

CMD ["/bin/bash"]
