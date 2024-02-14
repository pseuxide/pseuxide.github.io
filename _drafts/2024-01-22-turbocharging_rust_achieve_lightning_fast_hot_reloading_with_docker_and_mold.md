---
title: "Turbocharging Rust: Achieve Lightning-Fast Hot Reloading with Docker and Mold"
date: 2024-01-22 14:06:00 +0900
categories: [docker]
tags: [docker, rust]     # TAG names should always be lowercase
img_path: /assets/img/posts/turbocharging_rust_achieve_lightning_fast_hot_reloading_with_docker_and_mold/
image:
  path: header.png
  lqip: /assets/img/posts/turbocharging_rust_achieve_lightning_fast_hot_reloading_with_docker_and_mold/header.svg
  alt: header
---

## Introduction

I recently tested several possible ways to speed up Rust development environment with docker.

## first idea: docker compose watch (slow)

October 2023, [docker compose watch](https://docs.docker.com/compose/file-watch/) has been publicly released which allows docker compose to take action on specific file changes.

this is an example of how to configure your compose.yaml

```yaml
version: "3.8"

services:
  server:
    container_name: server
    # stuff...
    develop:  # <------- this block is what you wanna add today
      watch:
        - action: rebuild
          path: ./src
```
{: file='compose.yaml'}

With this, docker compose automatically run what you specify in the `action:` when any changes happen to files in `path:`. Because I assume this is a Rust project, ./src is the directory containing all the Rust code so i put `./src` in path.

about action, there is 3 type of action you can hook:

- rebuild: docker compose build a new image and replace it with currently running one.
- sync: watch host's files and apply same change to service container's file simultaniously
- sync + restart: sync then restart the container automatically.

This compose's new feature seems great, however turns out rebuilding everytime is significantly slow and it can't be a good friend for web backend development considering the number of times you save files. (of course)

## the best idea: mold + cargo-watch (blazingly fast)

After some hard grinding, I've found the most time-efficient way to auto-recompile Rust code. And that is, using [cargo-watch](https://crates.io/crates/cargo-watch) in conjunction with [mold](https://github.com/rui314/mold).

I assume you already know cargo-watch. It's famous tool to watch rust's code and build again when files get any changes. You can do auto-recompile just with cargo-watch to be honest. But Rust by itself has a slow build time. It's vEry VeRy slow. Even for small projects, you can bake your favorite bread and enjoy breakfast while it's building. That's why we use mold as well.

For those who don't know what the heck mold is:
> mold is a faster drop-in replacement for existing Unix linkers. It is several times quicker than the LLVM lld linker, the second-fastest open-source linker, which I initially developed a few years ago. mold aims to enhance developer productivity by minimizing build time, particularly in rapid debug-edit-rebuild cycles.

You can tell how fast it is by following comparison image.

![comparison](comparison.png)
_when linking final debuginfo-enabled executables for major large programs on a simulated 8-core, 16-thread machine_

And because Rust uses LLVM lld as a default linker, ...well if im not mistaken, using mold makes building time considerably faster.

How to use mold? well it's easy as this

```shell
mold -run cargo run
```

or with cargo-watch,

```shell
cargo watch -s 'mold -run cargo run'
```

that'd be it.

### Even go further: use docker compose with it

I personally wanted to develop in docker to encapsulate every dependencies.

Here's my compose.yaml and Dockerfile. I keep it as small as possible but for caching and stuff, ask chatGPT later if you want.

```yaml
version: "3.8"

services:
  server:
    container_name: server
    build:
      context: .
      dockerfile: Dockerfile # specifying which Dockerfile to use.
    command: sh -c "cargo watch -x fmt -s 'mold -run cargo run'" # this is the entry point and doing cargo watch
    ports: # port binding, the host's 8080 port will be bound to container's 8080 port.
      - "8080:8080"
```
{: file='compose.yaml'}

```Dockerfile
ARG RUST_VERSION=1.76.0
ARG APP_NAME=server

# use rust:1.76.0 image and label it 'dev'
FROM rust:${RUST_VERSION} AS dev

# Use apt-get to update and install packages
RUN apt-get update && apt-get install -y \
    clang \
    git

# install cargo-watch
RUN cargo install cargo-watch

# git clone mold and build from source using cmake
RUN git clone https://github.com/rui314/mold.git \
  && mkdir /mold/build \
  && cd /mold/build \
  && git checkout v2.4.0 \
  && ../install-build-deps.sh \
  && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=/usr/bin/c++ .. \
  && cmake --build . -j $(nproc) \
  && cmake --install .

WORKDIR /app

# copy host's ./src to container's ./src
COPY ./src ./src
COPY Cargo.toml Cargo.lock ./
```
{: file='Dockerfile'}

Everythings ready, now you run `docker compose up --build -d` and you have full-automated Rust development environment.
Only one drawback I would say to use this is it takes some time to build the container when start up. for me It took 5 mins or something I guess even with small project.