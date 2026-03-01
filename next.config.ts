import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",
  turbopack: {},
  // NOTE: Security headers (CSP, COOP, COEP, X-Frame-Options, etc.)
  // must be configured on your hosting platform (Vercel, Netlify, nginx)
  // since output: "export" produces static HTML.
  // See public/_headers or deployment docs for recommended header config.
};

export default nextConfig;
