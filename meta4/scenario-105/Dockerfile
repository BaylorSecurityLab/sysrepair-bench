FROM --platform=linux/amd64 debian:bookworm-slim

# Next.js middleware auth bypass (CVE-2025-29927)
# The x-middleware-subrequest header allows skipping middleware auth checks.
# Vulnerable state: no reverse proxy to strip the header — requests reach
# Next.js directly and the header is honoured, bypassing authentication.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Minimal Next.js app that demonstrates the middleware auth bypass
RUN npm init -y && \
    npm install next@14.1.0 react@18 react-dom@18

# App source — pages and middleware
RUN mkdir -p pages

# Public landing page
RUN cat > pages/index.js <<'EOF'
export default function Home() {
  return <h1>Public page</h1>;
}
EOF

# Protected page — only reachable if middleware allows it
RUN cat > pages/protected.js <<'EOF'
export default function Protected() {
  return <h1>Secret data</h1>;
}
EOF

# Middleware: block /protected unless Authorization header present.
# CVE-2025-29927: when x-middleware-subrequest header is set, Next.js skips
# middleware entirely — so the auth check is bypassed.
RUN cat > middleware.js <<'EOF'
import { NextResponse } from "next/server";

export function middleware(request) {
  const auth = request.headers.get("authorization");
  if (!auth) {
    return new NextResponse("Unauthorized", { status: 401 });
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/protected"],
};
EOF

RUN cat > next.config.js <<'EOF'
/** @type {import('next').NextConfig} */
const nextConfig = {};
module.exports = nextConfig;
EOF

# Pre-build the app so startup is fast
RUN npx next build

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 3000

CMD ["npx", "next", "start", "-p", "3000"]
