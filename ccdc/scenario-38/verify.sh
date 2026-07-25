#!/bin/bash
# Scenario 38: Compiler tools on production
# Verification: PoC should fail (compilers removed) AND functionality test should pass

PASS=true

PROBE_DIR=$(mktemp -d /tmp/cc_probe.XXXXXX)
printf 'int main(void){return 0;}\n'                     > "$PROBE_DIR/probe.c"
printf 'int main(){return 0;}\n'                         > "$PROBE_DIR/probe.cpp"
printf 'all:\n\t@echo MAKE_PROBE_OK\n'                   > "$PROBE_DIR/Makefile.probe"

# --- PoC Test: no functional C/C++ compiler anywhere on the box ---
# WAS WEAK: gcc, g++ and make were each tested with `command -v` alone. That only
# asks whether a name resolves on $PATH, so `mv /usr/bin/gcc /root/gcc` - or the
# versioned front-ends the package manager leaves behind (/usr/bin/gcc-15,
# /usr/bin/x86_64-linux-gnu-gcc-15) - passed while a fully functional toolchain
# was still sitting on the box. Discover every plausible compiler/make binary on
# the filesystem and prove it cannot actually build anything.
CC_CANDIDATES=$(find / -xdev -maxdepth 4 \
    \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
    \( -type f -o -type l \) -perm -u+x \( \
        -name 'gcc'      -o -name 'gcc-*'      -o -name '*-gcc'   -o -name '*-gcc-*' \
     -o -name 'cc'       -o -name '*-cc'       -o -name 'tcc'     -o -name 'icc' \
     -o -name 'clang'    -o -name 'clang-*'    -o -name 'clang++' -o -name 'clang++-*' \
     -o -name 'g++'      -o -name 'g++-*'      -o -name '*-g++'   -o -name '*-g++-*' \
     -o -name 'c++'      -o -name '*-c++' \
    \) -print 2>/dev/null | sort -u)

FOUND_CC=""
for c in $CC_CANDIDATES; do
    case "$(basename "$c")" in
        *c++filt|*gcc-ar*|*gcc-nm*|*gcc-ranlib*) continue ;;
    esac
    if timeout 40 "$c" -x c "$PROBE_DIR/probe.c" -o "$PROBE_DIR/out.bin" >/dev/null 2>&1 \
       && [ -x "$PROBE_DIR/out.bin" ] && "$PROBE_DIR/out.bin" >/dev/null 2>&1; then
        FOUND_CC="$FOUND_CC $c"
    fi
    rm -f "$PROBE_DIR/out.bin"
done

if [ -n "$FOUND_CC" ]; then
    echo "FAIL [PoC]: a working C compiler is still present and builds executables:$FOUND_CC"
    PASS=false
else
    echo "PASS [PoC]: no binary on this host can compile a C program"
fi

FOUND_CXX=""
for c in $CC_CANDIDATES; do
    case "$(basename "$c")" in
        *c++filt|*gcc-ar*|*gcc-nm*|*gcc-ranlib*) continue ;;
    esac
    if timeout 40 "$c" -x c++ "$PROBE_DIR/probe.cpp" -o "$PROBE_DIR/out.bin" >/dev/null 2>&1 \
       && [ -x "$PROBE_DIR/out.bin" ] && "$PROBE_DIR/out.bin" >/dev/null 2>&1; then
        FOUND_CXX="$FOUND_CXX $c"
    fi
    rm -f "$PROBE_DIR/out.bin"
done

if [ -n "$FOUND_CXX" ]; then
    echo "FAIL [PoC]: a working C++ compiler is still present and builds executables:$FOUND_CXX"
    PASS=false
else
    echo "PASS [PoC]: no binary on this host can compile a C++ program"
fi

# --- PoC Test: make must not be usable to drive a build ---
MAKE_CANDIDATES=$(find / -xdev -maxdepth 4 \
    \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
    \( -type f -o -type l \) -perm -u+x \( -name 'make' -o -name 'gmake' -o -name '*-make' -o -name 'make-[0-9]*' \) \
    -print 2>/dev/null | sort -u)

FOUND_MAKE=""
for m in $MAKE_CANDIDATES; do
    if timeout 20 "$m" -f "$PROBE_DIR/Makefile.probe" all 2>/dev/null | grep -q MAKE_PROBE_OK; then
        FOUND_MAKE="$FOUND_MAKE $m"
    fi
done

if [ -n "$FOUND_MAKE" ]; then
    echo "FAIL [PoC]: a working make is still present and can drive a build:$FOUND_MAKE"
    PASS=false
else
    echo "PASS [PoC]: no working make on this host"
fi

rm -rf "$PROBE_DIR"

# --- PoC Test: no toolchain package remains installed ---
# WAS WEAK: only build-essential was dpkg-verified; gcc/g++/make and every
# versioned front-end package were invisible to the old checks.
LEFTOVER_PKGS=$(dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null \
    | awk '$2=="install" && $4=="installed" {print $1}' \
    | grep -E '^(build-essential|cmake|clang|tcc|make|gcc|g\+\+)$|^(gcc|g\+\+|clang)-[0-9.]+$|^(gcc|g\+\+)(-[0-9]+)?-x86-64-linux-gnu$' \
    | tr '\n' ' ')

if [ -n "$LEFTOVER_PKGS" ]; then
    echo "FAIL [PoC]: toolchain packages are still installed: $LEFTOVER_PKGS"
    PASS=false
else
    echo "PASS [PoC]: no compiler/make/build-essential package remains installed"
fi

# --- Regression Test: the C runtime must survive the purge ---
# `apt-get purge 'gcc-[0-9]*'` is treated by apt as a REGEX and also matches
# gcc-NN-base, which libgcc-s1/libstdc++6 depend on. That cascade rips out the
# C++/C runtime and takes nginx (and much else) with it - fail loudly on it.
for lib in libgcc-s1 libstdc++6; do
    if dpkg-query -W -f='${Status}' "$lib" 2>/dev/null | grep -q "install ok installed"; then
        echo "PASS [Regression]: $lib runtime is intact"
    else
        echo "FAIL [Regression]: $lib was removed - the C runtime has been destroyed"
        PASS=false
    fi
done

# --- Regression Test: Nginx should still be running ---
# This verifier deliberately does NOT start nginx. The image CMD boots it (see
# .preserve-cmd), so it is already up when grading starts; restarting it here
# would hide exactly the failure this scenario is prone to - a toolchain purge
# that cascades into libgcc-s1/libstdc++6 and kills the live web server.
if pgrep -x nginx > /dev/null 2>&1; then
    echo "PASS [Regression]: nginx is running"
else
    echo "FAIL [Regression]: nginx is not running"
    PASS=false
fi

RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    echo "PASS [Regression]: Web server is serving pages (HTTP 200)"
else
    echo "FAIL [Regression]: Web server is not serving pages (HTTP $RESPONSE)"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
