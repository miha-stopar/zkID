# OpenAC Mobile Wallet-Unit-PoC 

Mobile App for [OpenAC Wallet-Unit-PoC](/wallet-unit-poc/ecdsa-spartan2/), support both Android and iOS through Flutter.

## Getting Started

### 1. Install the Mopro CLI Tool

```sh
cargo install mopro-cli
```

### 2. Android Configuration (Android targets only)

Before building for Android, configure the Android NDK environment variables. The Rust FFI bindings require NDK for cross-compilation.

1. Install NDK via Android Studio: `SDK Manager > SDK Tools > NDK (Side by Side)`

2. Set environment variables in your shell config (`~/.zshrc` or `~/.bashrc`):

    ```bash
    # Android SDK
    export ANDROID_HOME="$HOME/Library/Android/sdk"

    # Find your NDK version
    ls $ANDROID_HOME/ndk  # e.g., 26.1.10909125

    # Set NDK path (replace version with yours)
    export NDK_PATH="$ANDROID_HOME/ndk/26.1.10909125"
    ```

3. Reload your shell or run `source ~/.zshrc`

> For more details, see [Mopro Prerequisites - Android Configuration](https://zkmopro.org/docs/prerequisites#android-configuration)

## 3. Flutter App

### 3(a). Generate Flutter Bindings

Build bindings for your project by executing:

```sh
# choose Flutter bindings with release mode
mopro build
```

### 3(b). Connect Devices or Run Emulators

```sh
# Check Available Devices
flutter devices

# Start iOS Simulator or Android Emulator
flutter emulator --launch <EMULATOR_TYPE>
```

### 3(c). Run Flutter with Release Mode

```sh
cd flutter
flutter run --release
```

## Note

### Excluded x86_64 iOS simulator in `mopro_flutter_bindings/ios/mopro_flutter_bindings.podspec`

```podspec
# Flutter.framework does not contain a i386 slice.
# exclude x86_64 since w2c2 is not supported on x86_64-ios simulator build
'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386 x86_64',
```
