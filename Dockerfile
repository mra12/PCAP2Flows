FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    argus-server \
    argus-client \
    git \
    libpcap-dev \
    curl \
    gnupg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN echo 'deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' \
    > /etc/apt/sources.list.d/security-zeek.list \
    && curl -fsSL \
    https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/Release.key \
    | gpg --dearmor \
    > /etc/apt/trusted.gpg.d/security-zeek.gpg \
    && apt-get update \
    && apt-get install -y zeek-6.0 \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/zeek/bin:/opt/pcap2flows-venv/bin:$PATH"

WORKDIR /opt

RUN git clone https://github.com/zeek-flowmeter/zeek-flowmeter.git \
    && cd zeek-flowmeter \
    && git checkout 047f297bde6d5dc773efdf5b50000aac5c117bf1

RUN /opt/zeek/bin/zkg install /opt/zeek-flowmeter --force

COPY snapshot/zeek-flowmeter/flowmeter.zeek \
    /opt/zeek/share/zeek/site/flowmeter/flowmeter.zeek

WORKDIR /app

COPY PCAP2Flows /app/PCAP2Flows

RUN python3 -m venv /opt/pcap2flows-venv

ENV PATH="/opt/zeek/bin:/opt/pcap2flows-venv/bin:$PATH"

RUN python3 -m pip install --no-cache-dir \
    dpkt==1.9.8 \
    multipledispatch==1.0.0 \
    numpy==2.5.2 \
    packaging==26.3 \
    pandas==3.0.5 \
    python-dateutil==2.9.0.post0 \
    scipy==1.18.0 \
    setuptools==84.0.0 \
    six==1.17.0 \
    GitPython \
    semantic-version

RUN python3 -m pip install --no-cache-dir \
    /app/PCAP2Flows/third_party/NTLFlowLyzer

WORKDIR /app/PCAP2Flows

CMD ["python3", "pcap2flows.py"]
