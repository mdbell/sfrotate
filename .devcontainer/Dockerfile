FROM ubuntu:22.04

# Install basics
RUN apt-get update && apt-get install -y \
    unzip wget curl git build-essential openjdk-17-jdk python3 cmake sudo \
    && rm -rf /var/lib/apt/lists/*

ARG ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT}
RUN mkdir -p $ANDROID_SDK_ROOT/cmdline-tools \
    && cd $ANDROID_SDK_ROOT \
    && wget https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O cmdline-tools.zip \
    && unzip cmdline-tools.zip -d . \
    && rm cmdline-tools.zip

ENV PATH=/opt/android-sdk/cmdline-tools/bin:/opt/android-sdk/platform-tools:$PATH

# Accept licenses and install NDK + platform tools
RUN yes | sdkmanager --sdk_root=${ANDROID_SDK_ROOT} \
    "platform-tools" \
    "platforms;android-21" \
    "ndk;27.0.12077973"

RUN wget https://dl.google.com/android/repository/android-ndk-r25b-linux.zip \
    && unzip android-ndk-r25b-linux.zip -d $ANDROID_SDK_ROOT/ndk \
    && rm android-ndk-r25b-linux.zip

ENV ANDROID_NDK=$ANDROID_SDK_ROOT/ndk/android-ndk-r25b
ENV PATH=$ANDROID_NDK:$PATH

# clang
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-15.0.6/clang+llvm-15.0.6-x86_64-linux-gnu-ubuntu-18.04.tar.xz && \
  tar -xf clang+llvm-15.0.6-x86_64-linux-gnu-ubuntu-18.04.tar.xz >/dev/null && \
  mv clang+llvm-15.0.6-x86_64-linux-gnu-ubuntu-18.04 llvm-15.0.6 && \
  rm clang+llvm-15.0.6-x86_64-linux-gnu-ubuntu-18.04.tar.xz

ENV CLANG_PATH=/llvm-15.0.6/bin
ENV PATH=$CLANG_PATH:$PATH

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

RUN cargo install cargo-ndk

RUN useradd -ms /bin/bash vscode

RUN echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER vscode
WORKDIR /workspace
