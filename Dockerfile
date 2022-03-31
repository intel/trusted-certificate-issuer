# Copyright 2021 Intel Corporation. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build the manager binary
FROM ubuntu:focal as builder

ARG GO_VERSION="1.17.1"
ARG SDK_VERSION="2.15.100.3"
ARG SGX_SDK_INSTALLER=sgx_linux_x64_sdk_${SDK_VERSION}.bin
ARG DCAP_VERSION="1.12.100.3"
ENV DEBIAN_FRONTEND=noninteractive
# SGX prerequisites
# hadolint ignore=DL3005,DL3008
RUN apt-get update \
  && apt-get install --no-install-recommends -y \
    ca-certificates \
    curl \
    linux-tools-generic \
    wget \
    unzip \
    protobuf-compiler \
    libprotobuf-dev \
    build-essential \
    git \
    gnupg \
  && update-ca-certificates \
# Add 01.org to apt for SGX packages
# hadolint ignore=DL4006
  && echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" >> /etc/apt/sources.list.d/intel-sgx.list \
  && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - \
# Install SGX PSW
  && apt-get update \
  && apt-get install --no-install-recommends -y \
    libsgx-enclave-common=${SDK_VERSION}-focal1 \
    libsgx-launch=${SDK_VERSION}-focal1 \
    libsgx-launch-dev=${SDK_VERSION}-focal1 \
    libsgx-epid=${SDK_VERSION}-focal1 \
    libsgx-epid-dev=${SDK_VERSION}-focal1 \
    libsgx-quote-ex=${SDK_VERSION}-focal1 \
    libsgx-quote-ex-dev=${SDK_VERSION}-focal1 \
    libsgx-urts=${SDK_VERSION}-focal1 \
    libsgx-uae-service=${SDK_VERSION}-focal1 \
    libsgx-ae-epid=${SDK_VERSION}-focal1 \
    libsgx-ae-le=${SDK_VERSION}-focal1 \
    libsgx-ae-pce=${SDK_VERSION}-focal1 \
    libsgx-ae-qe3=${DCAP_VERSION}-focal1 \
    libsgx-ae-qve=${DCAP_VERSION}-focal1 \
    libsgx-dcap-ql=${DCAP_VERSION}-focal1 \
    libsgx-dcap-ql-dev=${DCAP_VERSION}-focal1 \
    libsgx-pce-logic=${DCAP_VERSION}-focal1 \
    libsgx-qe3-logic=${DCAP_VERSION}-focal1 \
    libsgx-dcap-default-qpl=${DCAP_VERSION}-focal1 \
  && apt-get clean \
  && ln -s /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1 /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so

# SGX SDK is installed in /opt/intel directory.
WORKDIR /opt/intel

# Install SGX SDK
# hadolint ignore=DL4006
RUN wget https://download.01.org/intel-sgx/sgx-linux/2.15/distro/ubuntu20.04-server/$SGX_SDK_INSTALLER \
  && chmod +x  $SGX_SDK_INSTALLER \
  && echo "yes" | ./$SGX_SDK_INSTALLER \
  && rm $SGX_SDK_INSTALLER \
  && ls -l /opt/intel/

# Tag/commit-id/branch to use for bulding CTK
ARG CTK_TAG="master"

# Intel crypto-api-toolkit prerequisites
#https://github.com/intel/crypto-api-toolkit#software-requirements
RUN set -x && apt-get update \
  && apt-get install --no-install-recommends -y \
    dkms libprotobuf17 autoconf \
    autotools-dev libc6-dev \
    libtool build-essential \
    opensc sudo \
    automake \
  && apt-get clean \
  && git clone https://github.com/intel/crypto-api-toolkit.git \
  && cd /opt/intel/crypto-api-toolkit \
  && git checkout ${CTK_TAG} -b v${CTK_TAG} \
  # disable building tests
  && sed -i -e 's;test;;g' ./src/Makefile.am \
  # disable enclave signing inside CTK
  && sed -i -e '/libp11SgxEnclave.signed.so/d' ./src/p11/trusted/Makefile.am \
  && ./autogen.sh \
  && ./configure --enable-dcap --with-token-path=/home/tcs-issuer \
  && make && make install

# Sign the enclave with custom config.
COPY enclave-config enclave-config
ENV SGX_SIGN=/opt/intel/sgxsdk/bin/x64/sgx_sign
RUN set -x; cd /opt/intel/crypto-api-toolkit/src/p11/trusted \
  && ${SGX_SIGN} gendata -enclave ./.libs/libp11SgxEnclave.so.0.0.0 -out /tmp/libp11SgxEnclave.unsigned -config /opt/intel/enclave-config/p11Enclave.config.xml \
  && /opt/intel/enclave-config/sign-enclave.sh -in /tmp/libp11SgxEnclave.unsigned -out /tmp/libp11SgxEnclave.signature -keyout /opt/intel/enclave-config/enclave-publickey.pem \
  && ${SGX_SIGN} catsig -enclave ./.libs/libp11SgxEnclave.so.0.0.0 \
                 -config /opt/intel/enclave-config/p11Enclave.config.xml \
                 -sig /tmp/libp11SgxEnclave.signature -key /opt/intel/enclave-config/enclave-publickey.pem \
                 -unsigned /tmp/libp11SgxEnclave.unsigned \
                 -out /usr/local/lib/libp11SgxEnclave.signed.so \
  && echo "----- Generated signed enclave! ----"

WORKDIR /workspace
RUN curl -L https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz | tar -zxf - -C / \
  && mkdir -p /usr/local/bin/ \
  && for i in /go/bin/*; do ln -s $i /usr/local/bin/; done

# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# Copy the go sources
COPY main.go main.go
COPY internal/ internal/
COPY controllers/ controllers/
COPY api/ api/
COPY vendor/ vendor/
COPY LICENSE LICENSE

RUN CGO_ENABLED=1 CGO_LDFLAGS="-L/usr/local/lib" GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o /manager main.go
RUN mkdir -p /usr/local/share/package-licenses \
  && cp /go/LICENSE /usr/local/share/package-licenses/go.LICENSE \
  && cp LICENSE /usr/local/share/package-licenses/tcs-issuer.LICENSE \
  && cp /opt/intel/crypto-api-toolkit/LICENSE.md /usr/local/share/package-licenses/crypto-api-toolkit.LICENSE

###
# Clean runtime image which supposed to
# contain all runtime dependecy packages
###
FROM ubuntu:focal as runtime

ARG SDK_VERSION="2.15.100.3"
ARG DCAP_VERSION="1.12.100.3"

RUN apt-get update \
  && apt-get install -y wget gnupg \
  && echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" >> /etc/apt/sources.list.d/intel-sgx.list \
  && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - \
  && sed -i '/deb-src/s/^# //' /etc/apt/sources.list \
  && apt-get update \
  && apt-get remove -y wget gnupg && apt-get autoremove -y \
  && bash -c 'set -o pipefail; apt-get install --no-install-recommends -y \
    libprotobuf17 \
    libsgx-enclave-common=${SDK_VERSION}-focal1 \
    libsgx-epid=${SDK_VERSION}-focal1 \
    libsgx-quote-ex=${SDK_VERSION}-focal1 \
    libsgx-urts=${SDK_VERSION}-focal1 \
    libsgx-ae-epid=${SDK_VERSION}-focal1 \
    libsgx-ae-qe3=${DCAP_VERSION}-focal1 \
    libsgx-dcap-ql=${DCAP_VERSION}-focal1 \
    libsgx-pce-logic=${DCAP_VERSION}-focal1 \
    libsgx-qe3-logic=${DCAP_VERSION}-focal1 \
    libsgx-dcap-default-qpl=${DCAP_VERSION}-focal1 \
    libsofthsm2 \
    # required for pkcs11-tool
    opensc | tee --append /usr/local/share/package-install.log' \
  && rm -rf /var/cache/* \
  && rm -rf  /var/log/*log /var/lib/apt/lists/* /var/log/apt/* /var/lib/dpkg/*-old /var/cache/debconf/*-old \
  && ln -s /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1 /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so

###
# Image that downloads the source packages for
#  the runtime GPL packages.
###
FROM ubuntu:focal as sources

COPY --from=runtime /usr/local/share/package-install.log /usr/local/share/package-install.log
COPY --from=runtime /usr/share/doc /tmp/runtime-doc

RUN sed -i '/deb-src/s/^# //' /etc/apt/sources.list \
  && apt-get update \
  # Install sources of GPL packages
  && mkdir /usr/local/share/package-sources && cd /usr/local/share/package-sources \
  && grep ^Get: /usr/local/share/package-install.log | grep -v sgx | cut -d ' ' -f 5,7 | \
      while read pkg version; do \
       if ! [ -f /tmp/runtime-doc/$pkg/copyright ]; then \
           echo "ERROR: missing copyright file for $pkg"; \
       fi; \
       if matches=$(grep -w -e MPL -e GPL -e LGPL /tmp/runtime-doc/$pkg/copyright); then \
          echo "INFO: downloading source of $pkg because of the following licenses:"; \
          echo "$matches" | sed -e 's/^/    /'; \
          apt-get source --download-only $pkg=$version || exit 1; \
       else \
          echo "INFO: not downloading source of $pkg, found no copyleft license"; \
       fi; \
      done \
  && apt-get clean

###
# Final trusted-certificate-issuer Image
###
FROM runtime as final

WORKDIR /
RUN useradd --create-home --home-dir /home/tcs-issuer --shell /bin/bash --uid 5000 --user-group tcs-issuer

COPY --from=builder /manager /tcs-issuer
COPY --from=builder /usr/local/lib/libp11* /usr/local/lib/
COPY --from=builder /opt/intel/enclave-config/enclave-publickey.pem /usr/local/share/enclave-publickey.pem
COPY --from=builder /usr/local/share/package-licenses /usr/local/share/package-licenses
COPY --from=sources /usr/local/share/package-sources /usr/local/share/package-sources

USER 5000:5000

ENV LD_LIBRARY_PATH="/usr/local/lib"

ENTRYPOINT ["/tcs-issuer"]
