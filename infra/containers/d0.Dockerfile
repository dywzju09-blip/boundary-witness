FROM docker.1panel.live/library/ubuntu@sha256:0d779ea97881505f5ef0039336ee85edba27519bdba968c284c86ee066a973c8

ARG SOURCE_COMMIT
ARG ARCHIVE_SHA256
ARG RUST_STABLE=1.97.0
ARG RUST_NIGHTLY=nightly-2026-07-08
ARG UBUNTU_APT_MIRROR=http://mirrors.ustc.edu.cn/ubuntu
ARG RUSTUP_INIT_URL=https://mirrors.tuna.tsinghua.edu.cn/rustup/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
ARG RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
ARG RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i "s|http://archive.ubuntu.com/ubuntu|${UBUNTU_APT_MIRROR}|g; s|http://security.ubuntu.com/ubuntu|${UBUNTU_APT_MIRROR}|g" /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        clang \
        curl \
        file \
        git \
        libsqlite3-dev \
        llvm \
        pkg-config \
        python3 \
        xz-utils \
        zstd \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_DIST_SERVER=${RUSTUP_DIST_SERVER}
ENV RUSTUP_UPDATE_ROOT=${RUSTUP_UPDATE_ROOT}
ENV PATH=/usr/local/cargo/bin:/opt/boundary-witness/bin:${PATH}

RUN curl --proto '=https' --tlsv1.2 -fsSL "${RUSTUP_INIT_URL}" -o /tmp/rustup-init \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "${RUST_STABLE}" \
    && rm /tmp/rustup-init \
    && rustup toolchain install "${RUST_NIGHTLY}" --profile minimal --component clippy --component rustfmt --component rustc-dev --component llvm-tools-preview \
    && rustup default "${RUST_STABLE}" \
    && chmod -R a+rX "${RUSTUP_HOME}" "${CARGO_HOME}"

WORKDIR /opt/boundary-witness/source
COPY . .

RUN cargo build --locked --bin bw \
    && mkdir -p /opt/boundary-witness/bin \
    && cp target/debug/bw /opt/boundary-witness/bin/bw \
    && (strip /opt/boundary-witness/bin/bw || true) \
    && bw --help >/dev/null

RUN useradd --create-home --uid 1000 --shell /bin/bash bw \
    && mkdir -p /workspace /evidence \
    && chown -R bw:bw /workspace /evidence

LABEL org.opencontainers.image.title="boundary-witness-d0"
LABEL org.opencontainers.image.description="BoundaryWitness D0 reproducible experiment runtime"
LABEL org.opencontainers.image.source="boundary-witness"
LABEL org.opencontainers.image.revision="${SOURCE_COMMIT}"
LABEL org.boundarywitness.archive-sha256="${ARCHIVE_SHA256}"
LABEL org.boundarywitness.base-image="docker.1panel.live/library/ubuntu@sha256:0d779ea97881505f5ef0039336ee85edba27519bdba968c284c86ee066a973c8"
LABEL org.boundarywitness.base-upstream="docker.io/library/ubuntu@sha256:0d779ea97881505f5ef0039336ee85edba27519bdba968c284c86ee066a973c8"
LABEL org.boundarywitness.rust-stable="${RUST_STABLE}"
LABEL org.boundarywitness.rust-nightly="${RUST_NIGHTLY}"
LABEL org.boundarywitness.ubuntu-apt-mirror="${UBUNTU_APT_MIRROR}"
LABEL org.boundarywitness.rustup-init-url="${RUSTUP_INIT_URL}"
LABEL org.boundarywitness.rustup-dist-server="${RUSTUP_DIST_SERVER}"
LABEL org.boundarywitness.rustup-update-root="${RUSTUP_UPDATE_ROOT}"

USER bw
WORKDIR /workspace

ENTRYPOINT ["/bin/bash", "-lc"]
CMD ["bw --help"]
