#!/bin/sh
set -eu

apt install -y \
    build-essential \
    git \
    meson \
    ninja-build \
    python3-pyelftools \
    clang \
    libclang-dev \
    libnuma-dev \
    pkg-config \
    libibverbs-dev \
    ibverbs-providers \
    libelf-dev \
    nettle-dev \
    libsystemd-dev \
    libbz2-dev \
    libzstd-dev \
    liblz4-dev \
    libacl1-dev
