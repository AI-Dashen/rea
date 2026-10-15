#!/data/data/com.termux/files/usr/bin/sh
set -eu

# Reproducible native Termux build for frida-node 17.23.3. This script never
# uses proot, Debian, Root, Android system files, or a system-wide installer.

project_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
work_root="${FRIDA_BUILD_ROOT:-$project_root/run/rea-upgrade-v2/frida-node-build-repro}"
version="17.23.3"
source_sha256="8551deb27f180bf7acf159e23ce94b660cbe8c03f4f89a17e628351625d1edf7"
lock_sha256="8d5bb32e318e9a57f4c43d6e003dd94bb8f66113b1896571ff640fb790d85086"
vala_commit="172348fa9123ff4a95d541c5f9e56837434c4b6e"
top_patch="$project_root/tools/rea/patches/0003-frida-node-17.23.3-termux-top-level.patch"
deps_patch="$project_root/tools/rea/patches/0004-frida-node-17.23.3-termux-subprojects.patch"

for command in node npm python clang ninja valac git curl tar patch pkg-config llvm-strip; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "MISSING_TERMUX_COMMAND: $command" >&2
    exit 2
  }
done
pkg-config --exists minizip-ng || {
  echo "MISSING_TERMUX_PACKAGE: libminizip-ng and libminizip-ng-static" >&2
  exit 2
}

mkdir -p "$work_root"
archive="$work_root/frida-$version.tgz"
source_root="$work_root/source"
vala_root="$work_root/vala-frida"
vala_build="$work_root/vala-build"
vala_prefix="$work_root/vala-prefix"
ndk_root="$work_root/ndk-r29-termux"

if [ ! -f "$archive" ]; then
  (cd "$work_root" && npm pack "frida@$version" --ignore-scripts >/dev/null)
fi
printf '%s  %s\n' "$source_sha256" "$archive" | sha256sum -c -

if [ ! -d "$source_root" ]; then
  mkdir -p "$source_root"
  tar -xzf "$archive" -C "$source_root" --strip-components=1
  curl --fail --location --silent --show-error \
    "https://raw.githubusercontent.com/frida/frida-node/$version/package-lock.json" \
    -o "$source_root/package-lock.json"
  printf '%s  %s\n' "$lock_sha256" "$source_root/package-lock.json" | sha256sum -c -
  (cd "$source_root" && patch -p1 < "$top_patch")
fi

if [ ! -d "$source_root/node_modules" ]; then
  (cd "$source_root" && npm ci --ignore-scripts)
fi

if [ ! -d "$vala_root/.git" ]; then
  git clone --filter=blob:none https://github.com/frida/vala.git "$vala_root"
  git -C "$vala_root" checkout --detach "$vala_commit"
fi
test "$(git -C "$vala_root" rev-parse HEAD)" = "$vala_commit"

if [ ! -x "$vala_prefix/bin/valac" ]; then
  python "$source_root/releng/meson/meson.py" setup "$vala_build" "$vala_root" \
    --prefix "$vala_prefix" --buildtype release -Db_lto=false
  ninja -C "$vala_build" -j1 install
fi

mkdir -p "$ndk_root/toolchains/llvm/prebuilt/android-arm64/bin"
mkdir -p "$ndk_root/toolchains/llvm/prebuilt/android-arm64/sysroot/usr/include/c++"
cat > "$ndk_root/source.properties" <<'PROPERTIES'
Pkg.Desc = Android NDK (Termux native compatibility shim)
Pkg.Revision = 29.0.14206865
PROPERTIES
for tool in clang clang++ llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-ranlib llvm-readelf llvm-strip; do
  ln -sfn "$(command -v "$tool")" "$ndk_root/toolchains/llvm/prebuilt/android-arm64/bin/$tool"
done
ln -sfn "$PREFIX/include/c++/v1" \
  "$ndk_root/toolchains/llvm/prebuilt/android-arm64/sysroot/usr/include/c++/v1"

export PATH="$vala_prefix/bin:$PATH"
export LD_LIBRARY_PATH="$vala_prefix/lib/vala-0.58:$vala_prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export ANDROID_NDK_ROOT="$ndk_root"
export FRIDA_TERMUX_NATIVE=1

mkdir -p "$source_root/deps"
ln -sfn "$vala_prefix" "$source_root/deps/toolchain-android-arm64"
python "$source_root/releng/deps.py" sync sdk android-arm64 \
  "$source_root/deps/sdk-android-arm64"

if [ ! -f "$source_root/build/build.ninja" ]; then
  (cd "$source_root" && ./configure --without-prebuilds=toolchain)
  (cd "$source_root" && patch -p1 < "$deps_patch")
  python "$source_root/releng/meson/meson.py" configure "$source_root/build" \
    -Dfrida-core:compat=disabled
fi

ninja -C "$source_root/build" -j1
node "$project_root/tools/rea/frida-node-probe.mjs" --module-root "$source_root"
