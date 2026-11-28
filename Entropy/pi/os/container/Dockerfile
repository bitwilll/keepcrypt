# The Pi image's build host (tasks/todo.md, M7 item C1; Q38 (e)): Debian trixie by digest, its
# packages from snapshot.debian.org at one fixed time, and rustup-init by version and SHA-256.
# pi/os/container.sh builds it and runs every pi/os command inside it. Each input was past the
# 14-day cool-off when pinned (cutoff 2026-11-08):
# - debian:trixie-20261104-slim, published 2026-11-05, multi-arch index digest below;
# - snapshot.debian.org debian 20261103T202439Z and debian-security 20261103T160100Z, the
#   archive states that 20261104T000000Z resolves to; apt checks their signatures with the
#   image's debian-archive-keyring, so plain http carries no trust;
# - rustup-init 1.29.3 (2026-11-03), x86_64-unknown-linux-gnu, its published SHA-256 checked here;
#   rustup then installs the toolchain rust-toolchain.toml pins, checking its manifest's hashes.
FROM debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 TZ=UTC
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' \
    'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261103T202439Z trixie main' \
    'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261103T202439Z trixie-updates main' \
    'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20261103T160100Z trixie-security main' \
    > /etc/apt/sources.list \
 && printf 'Acquire::Retries "5";\nAPT::Install-Recommends "false";\n' > /etc/apt/apt.conf.d/90keepcrypt \
 && apt-get update \
 && apt-get install -y bash bc binutils build-essential bzip2 ca-certificates cpio curl diffutils file \
    findutils gzip lzip make patch perl python3 rsync sed tar unzip wget xz-utils \
 && rm -rf /var/lib/apt/lists/* \
 && dpkg-query -W -f '${Package} ${Version}\n' > /etc/keepcrypt-packages.txt

ENV RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/opt/rust/cargo PATH=/opt/rust/cargo/bin:$PATH
COPY rust-toolchain.toml /tmp/toolchain/rust-toolchain.toml
RUN curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/rustup-init \
      https://static.rust-lang.org/rustup/archive/1.29.3/x86_64-unknown-linux-gnu/rustup-init \
 && echo 'b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55  /tmp/rustup-init' | sha256sum -c - \
 && chmod 0755 /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none \
 && rm /tmp/rustup-init \
 && cd /tmp/toolchain && rustup toolchain install && rustc --version && cargo --version \
 && rm -rf /tmp/toolchain \
 && chmod -R a+rwX /opt/rust
