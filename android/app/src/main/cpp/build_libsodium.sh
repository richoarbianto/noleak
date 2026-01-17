#!/bin/bash
# Build libsodium for Android
# Prerequisites: Android NDK must be installed and ANDROID_NDK_HOME set

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBSODIUM_DIR="/tmp/libsodium-stable"
OUTPUT_DIR="${SCRIPT_DIR}/libsodium/lib"

if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "Error: ANDROID_NDK_HOME is not set"
    echo "Please set it to your Android NDK path, e.g.:"
    echo "  export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/25.1.8937393"
    exit 1
fi

echo "Building libsodium for Android..."
echo "NDK: $ANDROID_NDK_HOME"
echo "Source: $LIBSODIUM_DIR"
echo "Output: $OUTPUT_DIR"

cd "$LIBSODIUM_DIR"

# Build for each architecture
for arch in armv7-a armv8-a x86 x86_64; do
    echo "Building for $arch..."
    ./dist-build/android-${arch}.sh
done

# Copy built libraries
echo "Copying libraries..."
# armv7 path stays stable
cp -f "$LIBSODIUM_DIR/libsodium-android-armv7-a/lib/libsodium.a" "$OUTPUT_DIR/armeabi-v7a/"

# arm64 directory may include +crypto suffix in recent releases
cp -f "$LIBSODIUM_DIR"/libsodium-android-armv8-a*/lib/libsodium.a "$OUTPUT_DIR/arm64-v8a/"

# x86 / x86_64
cp -f "$LIBSODIUM_DIR/libsodium-android-i686/lib/libsodium.a" "$OUTPUT_DIR/x86/"
cp -f "$LIBSODIUM_DIR/libsodium-android-westmere/lib/libsodium.a" "$OUTPUT_DIR/x86_64/"

echo "Done! libsodium built for all Android architectures."
