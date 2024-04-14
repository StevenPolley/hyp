# Build environment container
# THIS CONTAINER IS NOT FOR RUNNING HYP, IT IS FOR BUILDING IT FROM SOURCE

FROM debian:stable
LABEL maintainer="himself@stevenpolley.net"

# Install build
RUN apt update -y && \
    apt upgrade -y && \
    apt install -y wget git clang linux-headers-amd64 libbpf-dev

# Install golang - Latest at: https://go.dev/dl/
RUN wget https://go.dev/dl/go1.22.2.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.2.linux-amd64.tar.gz && \
    rm -rf *.tar.gz && \
    echo "export PATH=$PATH:/usr/local/go/bin" >> /root/.profile && source /root/.profile && \
    