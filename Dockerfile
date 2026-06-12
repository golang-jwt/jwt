FROM golang:1.21-bullseye

# ═══════════════════════════════════════════════
# Step 1/4: Install system dependencies
# ═══════════════════════════════════════════════
RUN echo "═══ [1/4] Installing dependencies... ═══" && \
    apt-get update -qq && \
    apt-get install -y -qq \
        cmake build-essential git ca-certificates \
        libssl-dev openssl \
        ninja-build \
    && rm -rf /var/lib/apt/lists/* && \
    echo "✅ Dependencies installed"

WORKDIR /app

# ═══════════════════════════════════════════════
# Step 2/4: Build liboqs (NIST PQC library)
# ═══════════════════════════════════════════════
RUN echo "═══ [2/4] Building liboqs from source... ═══" && \
    git clone --depth 1 --branch 0.10.0 https://github.com/open-quantum-safe/liboqs && \
    cd liboqs && mkdir build && cd build && \
    cmake -GNinja .. \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOQS_USE_OPENSSL=OFF \
        -DBUILD_SHARED_LIBS=ON \
        2>&1 | tail -5 && \
    echo "→ Compiling (this takes ~3 mins)..." && \
    cmake --build . --parallel $(nproc) 2>&1 | tail -10 && \
    cmake --install . && \
    ldconfig && \
    cd /app && rm -rf liboqs && \
    echo "✅ liboqs built and installed!"

# ═══════════════════════════════════════════════
# Step 3/4: Build Φ-JWT Server
# ═══════════════════════════════════════════════
ENV CGO_ENABLED=1
COPY . .
RUN echo "═══ [3/4] Building Φ-JWT Server... ═══" && \
    cd cmd/phi_server && \
    go build -o /phi-server . && \
    echo "✅ Φ-JWT Server built!"

# ═══════════════════════════════════════════════
# Step 4/4: Ready
# ═══════════════════════════════════════════════
RUN echo "═══ [4/4] Φ-JWT Container Ready! ═══" && \
    echo "╔══════════════════════════════════════════════╗" && \
    echo "║  Φ-JWT: Post-Quantum Hybrid JWT Server        ║" && \
    echo "║  Falcon-512 PQC | φ-DNA | Divine Noise 40bit  ║" && \
    echo "║  ΦΩ0 — I AM THAT I AM                       ║" && \
    echo "╚══════════════════════════════════════════════╝"

EXPOSE 8443
CMD ["/phi-server"]
