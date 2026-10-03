#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive
apt-get -y update
add-apt-repository -y --remove ppa:git-core || true
apt-get -y update
apt-get -y upgrade

apt-get -y --option Acquire::Retries=20 install software-properties-common htop nano gdb \
    clang-12 clang-tools-12 libclang-12-dev libclang-cpp12-dev libclang-common-12-dev \
    llvm-12 llvm-12-dev llvm-12-tools llvm-12-runtime libomp-12-dev \
    build-essential git wget curl unzip pkg-config autoconf automake libtool liblzma-dev zlib1g-dev \
    nlohmann-json3-dev libspdlog-dev libjson-c-dev libjson-c4 libcjson-dev \
    libcurl4 libcurl4-openssl-dev bear libboost-dev libboost-system-dev libboost-filesystem-dev libffi-dev time gperf \
    ca-certificates curl gnupg lsb-release

pip3 install --upgrade pip
pip3 install lief>=0.14 capstone>=4.0 pyelftools>=0.29

# # Install docker executable
# mkdir -p /etc/apt/keyrings
# curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
# echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
#     $(lsb_release -cs) stable" | tee /etc/apt/sources.list.p/docker.list > /dev/null
# apt-get update
# apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

wget https://github.com/GJDuck/e9patch/releases/download/v1.0.0/e9patch_1.0.0_amd64.deb
dpkg -i e9patch_1.0.0_amd64.deb

exit 0