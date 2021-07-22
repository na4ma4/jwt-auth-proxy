FROM ubuntu:bionic as builder

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

## Install curl, ca-certificates and tzdata
RUN apt-get update && \
  apt-get install --no-install-recommends --quiet --yes curl ca-certificates tzdata bash && \
  update-ca-certificates

## Remove symlinks outside /etc/ssl/certs
COPY scripts/replace-links-in-ssl-certs.sh /
RUN /replace-links-in-ssl-certs.sh

FROM scratch

COPY --from=builder /etc/ssl/certs/ /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

ENV HTTP_PORT="80" AUDIENCE="tls-web-client-auth" BACKEND_URL=""

EXPOSE 80/tcp
ENTRYPOINT [ "/jwt-auth-proxy" ]
COPY jwt-auth-proxy /
