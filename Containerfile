ARG DEBIAN_IMAGE=docker.io/library/debian:13-slim

FROM ${DEBIAN_IMAGE} AS sipp-builder

ARG SIPP_VERSION=v3.7.7
ARG SIPP_RELEASE=3.7.7
ARG SIPP_SHA256=e55b15f567760e9febeef366a1ab51a5239d197a132ce931b78c826d22d31e69

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        cmake \
        curl \
        g++ \
        libncurses-dev \
        libpcap-dev \
        libsctp-dev \
        libssl-dev \
        ninja-build \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN curl --fail --location --show-error \
        "https://github.com/SIPp/sipp/releases/download/${SIPP_VERSION}/sipp-${SIPP_RELEASE}.tar.gz" \
        --output /tmp/sipp.tar.gz \
    && echo "${SIPP_SHA256}  /tmp/sipp.tar.gz" | sha256sum --check - \
    && mkdir -p /src/sipp \
    && tar --extract --gzip --file /tmp/sipp.tar.gz \
        --directory /src/sipp --strip-components=1 \
    && rm /tmp/sipp.tar.gz

RUN cmake \
        -S /src/sipp \
        -B /build/sipp \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DUSE_PCAP=1 \
        -DUSE_SCTP=1 \
        -DUSE_SSL=1 \
    && cmake --build /build/sipp --parallel

FROM ${DEBIAN_IMAGE} AS pjsip-builder

ARG PJSIP_VERSION=2.17
ARG PJSIP_SHA256=065fe06c06788d97c35f563796d59f00ce52fe9558a52d7b490a042a966facce

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        libasound2-dev \
        libopus-dev \
        libsrtp2-dev \
        libssl-dev \
        libuuid1 \
        pkg-config \
        uuid-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl --fail --location --show-error \
        "https://github.com/pjsip/pjproject/archive/refs/tags/${PJSIP_VERSION}.tar.gz" \
        --output /tmp/pjproject.tar.gz \
    && echo "${PJSIP_SHA256}  /tmp/pjproject.tar.gz" | sha256sum --check - \
    && mkdir -p /src/pjproject \
    && tar --extract --gzip --file /tmp/pjproject.tar.gz \
        --directory /src/pjproject --strip-components=1 \
    && rm /tmp/pjproject.tar.gz

RUN cd /src/pjproject \
    && printf '%s\n' \
        '#define PJ_HAS_IPV6 1' \
        '#include <pj/config_site_sample.h>' \
        > pjlib/include/pj/config_site.h \
    && ./configure \
        --disable-video \
        --enable-epoll \
        --with-external-srtp \
    && make dep \
    && make --jobs="$(nproc)" \
    && find pjsip-apps/bin -maxdepth 1 -type f -name 'pjsua-*' \
        -exec cp '{}' /build-pjsua ';' \
    && test -x /build-pjsua

FROM ${DEBIAN_IMAGE}

ARG SIPP_VERSION=v3.7.7
ARG PJSIP_VERSION=2.17
ARG BOOFUZZ_VERSION=0.4.2
ARG PYYAML_VERSION=6.0.3
ARG SCAPY_VERSION=2.6.1
ARG SIPVICIOUS_VERSION=0.3.8
ARG URWID_VERSION=4.0.4

LABEL org.opencontainers.image.title="sippycup"
LABEL org.opencontainers.image.description="Network-only SIP, RTP, RTCP, and VoIP assessment toolbox"
LABEL org.opencontainers.image.version="${SIPP_VERSION}"
LABEL dev.sippycup.pjsip.version="${PJSIP_VERSION}"

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/voip-tools/bin:${PATH}"
ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" \
        | debconf-set-selections \
    && echo "iperf3 iperf3/start_daemon boolean false" \
        | debconf-set-selections \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        baresip \
        age \
        bash \
        bash-completion \
        ca-certificates \
        conntrack \
        coturn \
        curl \
        dnsutils \
        ethtool \
        ffmpeg \
        gstreamer1.0-plugins-base \
        gstreamer1.0-plugins-good \
        gstreamer1.0-tools \
        hping3 \
        iperf3 \
        iproute2 \
        iputils-ping \
        jq \
        less \
        libncursesw6 \
        libopus0 \
        libpcap0.8t64 \
        libsctp1 \
        libsrtp2-1 \
        libssl3t64 \
        libuuid1 \
        lsof \
        mtr-tiny \
        minisign \
        netcat-openbsd \
        ngrep \
        nftables \
        nmap \
        openssl \
        passt \
        procps \
        python3 \
        python3-pip \
        python3-venv \
        sipsak \
        sngrep \
        socat \
        sox \
        sslscan \
        strace \
        tcpdump \
        tcpreplay \
        termshark \
        testssl.sh \
        tini \
        traceroute \
        tshark \
        util-linux \
        vim-tiny \
        whois \
    && rm -rf /var/lib/apt/lists/*

ARG MCP_VERSION=1.27.2

RUN python3 -m venv /opt/voip-tools \
    && /opt/voip-tools/bin/pip install --no-cache-dir \
        "boofuzz==${BOOFUZZ_VERSION}" \
        "PyYAML==${PYYAML_VERSION}" \
        "scapy==${SCAPY_VERSION}" \
        "sipvicious==${SIPVICIOUS_VERSION}" \
        "urwid==${URWID_VERSION}" \
        "mcp==${MCP_VERSION}"

COPY --from=sipp-builder /build/sipp/sipp /usr/local/bin/sipp
COPY --from=pjsip-builder /build-pjsua /usr/local/bin/pjsua
COPY bin/campaign /usr/local/bin/campaign
COPY bin/campaign-sipp-runner /usr/local/bin/campaign-sipp-runner
COPY bin/campaign-loopback-uas /usr/local/bin/campaign-loopback-uas
COPY bin/campaign-integration-selftest /usr/local/bin/campaign-integration-selftest
COPY bin/container-preflight /usr/local/bin/sippycup-preflight
COPY bin/container-report /usr/local/bin/sippycup-report
COPY bin/selftest /usr/local/bin/sippycup-selftest
COPY bin/sippycup-assert /usr/local/bin/sippycup-assert
COPY bin/sippycup-chaos /usr/local/bin/sippycup-chaos
COPY bin/sippycup-diff /usr/local/bin/sippycup-diff
COPY bin/sippycup-evidence /usr/local/bin/sippycup-evidence
COPY bin/sippycup-pack /usr/local/bin/sippycup-pack
COPY bin/sippycup-envelope /usr/local/bin/sippycup-envelope
COPY bin/sippycup-media /usr/local/bin/sippycup-media
COPY bin/sippycup-media-echo /usr/local/bin/sippycup-media-echo
COPY bin/sippycup-mcp /usr/local/bin/sippycup-mcp
COPY bin/sippycup-mcp-live /usr/local/bin/sippycup-mcp-live
COPY bin/sippycup-torture /usr/local/bin/sippycup-torture
COPY bin/sippycup-ui /usr/local/bin/sippycup-ui
COPY bin/sippycup-resilience /usr/local/bin/sippycup-resilience
COPY bin/sippycup-workbench /usr/local/bin/sippycup-workbench
COPY bin/sippycup-web-security /usr/local/bin/sippycup-web-security
COPY bin/web-security-profile /usr/local/bin/web-security-profile
COPY bin/web-security-evidence /usr/local/bin/web-security-evidence
COPY bin/smoke /usr/local/bin/sippycup-smoke
COPY lib/sippycup /usr/local/lib/sippycup
COPY lib/sippycup_oracle /usr/local/lib/sippycup_oracle
COPY lib/sippycup_chaos /usr/local/lib/sippycup_chaos
COPY lib/sippycup_torture /usr/local/lib/sippycup_torture
COPY lib/sippycup_tui /usr/local/lib/sippycup_tui
COPY lib/sippycup_learn /usr/local/lib/sippycup_learn
COPY lib/sippycup_media /usr/local/lib/sippycup_media
COPY lib/sippycup_mcp /usr/local/lib/sippycup_mcp
COPY lib/sippycup_resilience /usr/local/lib/sippycup_resilience
COPY lib/sippycup_webrtc /usr/local/lib/sippycup_webrtc
COPY lib/sippycup_workbench /usr/local/lib/sippycup_workbench
COPY lib/sippycup_web_security /usr/local/lib/sippycup_web_security
COPY media /usr/local/share/sippycup/media
COPY profiles/chaos /usr/local/share/sippycup/chaos-profiles
COPY README.md /usr/local/share/sippycup/README.md
COPY config/commands.tsv /usr/local/share/sippycup/config/commands.tsv
COPY docs /usr/local/share/sippycup/docs
COPY schemas /usr/local/share/sippycup/schemas
COPY examples/evidence-pack/sanitized-evidence.tar /usr/local/share/sippycup/fixtures/sanitized-evidence.tar
COPY tools/generate_audio_canaries.py /usr/local/libexec/sippycup/generate_audio_canaries.py
COPY completions/campaign.bash /usr/share/bash-completion/completions/campaign

RUN chmod 0755 \
        /usr/local/bin/campaign \
        /usr/local/bin/campaign-sipp-runner \
        /usr/local/bin/campaign-loopback-uas \
        /usr/local/bin/campaign-integration-selftest \
        /usr/local/bin/sipp \
        /usr/local/bin/sippycup-preflight \
        /usr/local/bin/sippycup-report \
        /usr/local/bin/sippycup-selftest \
        /usr/local/bin/sippycup-assert \
        /usr/local/bin/sippycup-chaos \
        /usr/local/bin/sippycup-diff \
        /usr/local/bin/sippycup-evidence \
        /usr/local/bin/sippycup-pack \
        /usr/local/bin/sippycup-envelope \
        /usr/local/bin/sippycup-media \
        /usr/local/bin/sippycup-media-echo \
        /usr/local/bin/sippycup-mcp \
        /usr/local/bin/sippycup-mcp-live \
        /usr/local/bin/sippycup-torture \
        /usr/local/bin/sippycup-ui \
        /usr/local/bin/sippycup-resilience \
        /usr/local/bin/sippycup-workbench \
        /usr/local/bin/sippycup-smoke \
    && mkdir -p /work \
    && printf '%s\n' \
        'alias ll="ls -alF"' \
        'alias sipcap="tshark -i any -f \"udp port 5060 or tcp port 5060 or tcp port 5061\""' \
        >> /root/.bashrc

WORKDIR /work
VOLUME ["/work"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/bin/bash"]
