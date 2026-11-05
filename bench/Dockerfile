
FROM rust:1.95-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY bitforge bitforge
COPY eventframe eventframe
COPY flux flux
COPY flux-iocp flux-iocp
RUN cargo build --locked --release -p flux --all-features

FROM debian:bookworm-slim

ARG SHAKA_VERSION=3.9.3
ARG SHAKA_SHA256=7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6
ARG BENTO4_BUILD=Bento4-SDK-1-6-0-641.x86_64-unknown-linux
ARG BENTO4_SHA256=d48dc6b164941212e5614237b4d9aeff81d4d111ee8b1508892764078a0870e8

RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg python3 ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /usr/local/bin/packager \
      "https://github.com/shaka-project/shaka-packager/releases/download/v${SHAKA_VERSION}/packager-linux-x64" \
 && echo "${SHAKA_SHA256}  /usr/local/bin/packager" | sha256sum -c - \
 && chmod +x /usr/local/bin/packager

RUN curl -fsSL -o /tmp/bento4.zip "https://www.bok.net/Bento4/binaries/${BENTO4_BUILD}.zip" \
 && echo "${BENTO4_SHA256}  /tmp/bento4.zip" | sha256sum -c - \
 && unzip -j /tmp/bento4.zip "${BENTO4_BUILD}/bin/mp4decrypt" -d /usr/local/bin \
 && chmod +x /usr/local/bin/mp4decrypt \
 && rm /tmp/bento4.zip

COPY --from=build /src/target/release/flux /usr/local/bin/flux
COPY bench/bench.py /bench/bench.py

ENTRYPOINT ["python3", "-I", "/bench/bench.py"]
CMD ["versions"]
