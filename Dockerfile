FROM alpine:3.23

RUN apk add --no-cache \
        git \
        make \
        musl-dev \
        go \
        clang21 \
        llvm \
        libbpf-dev \
        linux-headers \
        bpftool \
    && ln -sf /usr/bin/clang-21 /usr/bin/clang

ENV GOPATH=/tmp/.go \
    GOCACHE=/tmp/.gocache \
    GOMODCACHE=/tmp/.gomodcache \
    CGO_ENABLED=0

WORKDIR /work
