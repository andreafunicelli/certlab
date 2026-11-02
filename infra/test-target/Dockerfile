# NOT EXERCISED in the authoring environment (Docker Hub unreachable there). Same layout as setup-local.sh.
# Build from the repository root:  docker build -f infra/test-target/Dockerfile -t cdp-test-target .
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server sudo openssl nginx apache2 haproxy ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
COPY infra/remote-helper /opt/cdp/infra/remote-helper
COPY infra/test-target /opt/cdp/infra/test-target
# setup-local.sh starts every daemon itself; the container then just stays alive.
ENTRYPOINT ["/bin/bash", "-c", "/opt/cdp/infra/test-target/setup-local.sh && exec tail -f /var/lib/cdp-test/sshd.log"]
EXPOSE 2222 8443 9443 10443
