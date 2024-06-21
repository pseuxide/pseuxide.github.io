---
title: "Hot reloading rust blazingly fast with Docker and Mold"
date: 2024-01-22 14:06:00 +0900
categories: [web, backend]
tags: [docker, rust]
img_path: /assets/img/posts/hot_reloading_rust_blazingly_fast_with_docker_and_mold/
image:
  path: header.png
  lqip: /assets/img/posts/hot_reloading_rust_blazingly_fast_with_docker_and_mold/header.svg
  alt: header
---

## Introduction

Welcome to this guide, where I'll be showing you how to develop a server in Rust with unparalleled efficiency. By 'efficiency,' I'm referring to significantly reducing the endless waiting periods for source code recompilation after every change.
I recently tested several possible ways to speed up Rust development with docker, then I've stumbled upon some viable and interesting ideas. I'm excited to share these insights with you.

The corresponding repository introduced in this article is this: [vxcall/dockerized-rust-hot-reload](https://github.com/vxcall/dockerized-rust-hot-reload)

## initial idea: docker compose watch (turned out 2b slow)

October 2023, [docker compose watch](https://docs.docker.com/compose/file-watch/) has been publicly released which allows docker compose to take certain 3 actions on specific file changes.

this is an example of how to configure your compose.yaml to enable docker compose watch

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

With this, u run `docker compose watch` command, then docker compose automatically take `action:` when any changes happen to files in `path:`. I didnt tell u but because this is a Rust project, `./src` is the suitable directory containing all the Rust code so i put `./src` in path.

about `action:`, there're 3 types of action you can hook:

- `rebuild`: docker compose build a new image and replace it with currently running one.
- `sync`: watch host's files and apply same change to service container's file simultaniously
- `sync + restart`: sync then restart the container automatically.

This compose's new feature seems great, however turns out rebuilding everytime is significantly slow and it can't be a good friend for web backend development considering the number of times you save files. (of course)

## the best idea: mold + cargo-watch (blazingly fast)

In my quest for efficiency, I've discovered the most time-saving approach to automatically recompile Rust code. This method involves leveraging [cargo-watch](https://crates.io/crates/cargo-watch) in tandem with [mold](https://github.com/rui314/mold).

You're likely familiar with cargo-watch, it's famous tool for monitoring changes in Rust code and triggering rebuilds. While it's entirely possible to facilitate auto-recompilation solely with cargo-watch, the inherent slow compilation time of Rust makes this less than ideal. It's vEry VeRy slow. Even for small projects, you can bake your favorite bread and enjoy breakfast while it's building. That's why we use mold as well.

For those who don't know what the heck mold is:
> mold is a faster drop-in replacement for existing Unix linkers. It is several times quicker than the LLVM lld linker, the second-fastest open-source linker, which I initially developed a few years ago. mold aims to enhance developer productivity by minimizing build time, particularly in rapid debug-edit-rebuild cycles.

The speed advantage of mold is evident in the following comparison image:

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

that'd be it. Let's see how it goes with real example in next section.

### Practical example: dockerized server code

Let's go even further, here I brought the simplest rust server code as well as Docker-related files. (I personally wanted to develop in docker to encapsulate every dependencies.)

Here's the rust server written with [Rocket-rs](https://rocket.rs/) which just because I recently used, whatever code will be fine.

```rs
#[macro_use]
extern crate rocket;

#[get("/jobs")]
fn jobs() -> &'static str {
    "all jobs"
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/api", routes![jobs])
}
```
{: file='src/main.rs'}

And here's my compose.yaml and Dockerfile.dev. If u think it looks overwhelming, don't worry there's same code in my GitHub so [refer to it](https://github.com/vxcall/dockerized-rust-hot-reload).

```yaml
version: "3.8"

services:
  server:
    container_name: server
    build:
      context: .
      dockerfile: Dockerfile.dev
    # here we invoke cargo-watch with mold, additionally I also run format by personal preferences lol
    command: sh -c "cargo watch -x fmt -s 'mold -run cargo run'"
    # just cache thing, u can ignore this
    volumes:
      - .:/app
      - cargo-registry:/usr/local/cargo/registry
      - cargo-git:/usr/local/cargo/git
      - target:/app/target
    environment:
      ROCKET_PORT: 8080
      ROCKET_ADDRESS: "0.0.0.0"
    ports:
      - "8080:8080"
# same cache thing.
volumes:
  cargo-registry:
  cargo-git:
  target:
```
{: file='compose.yaml'}

```Dockerfile
ARG RUST_VERSION=1.76.0
ARG APP_NAME=server

FROM rust:${RUST_VERSION} AS dev

# Use apt-get to update and install packages
RUN apt-get update && apt-get install -y \
    clang

# install cargo-watch
RUN cargo install cargo-watch

# install format tool
RUN rustup component add rustfmt

RUN curl -L https://github.com/rui314/mold/releases/download/v2.30.0/mold-2.30.0-x86_64-linux.tar.gz -o mold-2.30.0-x86_64-linux.tar.gz \
    && tar -zxvf mold-2.30.0-x86_64-linux.tar.gz \
    && cd mold-2.30.0-x86_64-linux \
    && cp -r bin/* /usr/local/bin/ \
    && cp -r lib/* /usr/local/lib/ \
    && ldconfig

WORKDIR /app

COPY ./src ./src
COPY Cargo.toml Cargo.lock ./
```
{: file='Dockerfile.dev'}

Everythings ready, now you run `docker compose up --build -d` and you have full-automated Rust development environment. When you change files under `src` directory the server will be reloaded. In this specific example, because it's tiny, it took 2 seconds to be hot-reloaded which would've taken 5 or 6 seconds normally with lld.
~~Only one drawback I would say is that it takes while to build the container when start up cuz it's building mold entirely from source code. I'm sure there's ways to lower the time tho.~~ I did a performance optimization, therefore it should be pretty quick.

## Conclusion

We've explored a powerful way to speed up Rust development by using Docker, cargo-watch, and mold. This setup significantly reduces waiting times for code recompilation, making your development process much faster and more efficient.

While setting up might take a bit of effort, especially building mold from scratch, the benefits are clear. Changes in your code reflect almost instantly, cutting down the usual wait and boosting your productivity.

In short, if you're looking for a way to make your Rust development quicker and more responsive, this Dockerized approach is worth trying. It's a game-changer for developers tired of slow compile times.