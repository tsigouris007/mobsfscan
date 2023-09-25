# Use a Python slim base image
FROM python:3.9-slim

# Switch to the root user
USER root

# Install packages: js, bash, grep, git, wget
RUN apt-get update && \
    apt-get install -y \
        bash \
        grep \
        git \
        wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pip install mobsfscan==0.3.4

# To add gh cli
RUN wget https://github.com/cli/cli/releases/download/v2.4.0/gh_2.4.0_linux_amd64.tar.gz -O /tmp/gh.tar.gz && \
    tar -xvf /tmp/gh.tar.gz -C /tmp && \
    mv /tmp/gh_*_linux_amd64/bin/gh /usr/local/bin/gh && \
    rm -rf /tmp/gh_*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x entrypoint.sh

COPY report.py /report.py
RUN chmod +x /report.py

# Create a user
# RUN adduser -D -g '' user
RUN groupadd user
RUN useradd -g user -s /bin/sh user
USER user
WORKDIR /data

ENTRYPOINT ["/entrypoint.sh"]
