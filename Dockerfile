# Dockerfile for compliancekit.
#
# Built by GoReleaser during release; the COPY assumes the binary
# already sits next to this file (goreleaser drops it there per
# .goreleaser.yaml's dockers.* stanza). For local 'docker build .'
# without goreleaser, run 'make build' first so bin/compliancekit
# exists, then 'docker build -t compliancekit -f Dockerfile .' from
# the same directory after copying bin/compliancekit beside this file.
#
# Base image is gcr.io/distroless/static-debian12 (nonroot variant):
#
#   - no shell, no package manager, no setuid binaries -- vastly
#     smaller attack surface than alpine or scratch+ca-certs.
#   - includes the Mozilla CA bundle at /etc/ssl/certs, which the
#     DigitalOcean API client needs.
#   - includes /etc/passwd entries for the `nonroot` user (uid 65532)
#     so the binary runs unprivileged out of the box.
#   - statically linked Go binary (CGO_ENABLED=0) needs no glibc, no
#     musl, no symlinks -- so the base does not need to provide them.

FROM gcr.io/distroless/static-debian12:nonroot

# OCI image labels duplicated here as a fallback; the goreleaser
# build_flag_templates set authoritative values at release time.
LABEL org.opencontainers.image.title="compliancekit" \
      org.opencontainers.image.description="Open-source compliance scanner for cloud and Linux infrastructure" \
      org.opencontainers.image.url="https://github.com/darpanzope/compliancekit" \
      org.opencontainers.image.source="https://github.com/darpanzope/compliancekit" \
      org.opencontainers.image.licenses="MIT"

COPY compliancekit /usr/local/bin/compliancekit

USER nonroot:nonroot
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/compliancekit"]
CMD ["--help"]
