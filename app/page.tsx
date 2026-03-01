"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Lock,
  Unlock,
  Type,
  Cpu,
  MemoryStick,
  Globe,
  ShieldCheck,
  Cog,
  Database,
  Gauge,
  ArrowRight,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  getSystemCapabilities,
  calculateSystemLimits,
  type SystemCapabilities,
  type SystemLimits,
} from "@/lib/system";

export default function DashboardPage() {
  const [caps, setCaps] = useState<SystemCapabilities | null>(null);
  const [limits, setLimits] = useState<SystemLimits | null>(null);

  useEffect(() => {
    const c = getSystemCapabilities();
    setCaps(c);
    setLimits(calculateSystemLimits(c));
  }, []);

  const tierColor =
    limits?.tier === "high"
      ? "bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20"
      : limits?.tier === "medium"
        ? "bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-yellow-500/20"
        : "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20";

  return (
    <div className="space-y-8">
      {/* Hero */}
      <div className="space-y-2">
        <h1 className="text-3xl font-bold tracking-tight">Encryption</h1>
        <p className="text-muted-foreground">
          Zero-knowledge, client-side AES-256-GCM encryption. Your data never
          leaves this browser.
        </p>
      </div>

      {/* Security badges */}
      <div className="flex flex-wrap gap-2">
        <Badge variant="secondary" className="gap-1.5">
          <ShieldCheck className="h-3 w-3" />
          AES-256-GCM
        </Badge>
        <Badge variant="secondary" className="gap-1.5">
          <Lock className="h-3 w-3" />
          Argon2id · WASM KDF
        </Badge>
        <Badge variant="secondary" className="gap-1.5">
          <Globe className="h-3 w-3" />
          Works Offline
        </Badge>
        <Badge variant="secondary" className="gap-1.5">
          <Cog className="h-3 w-3" />
          Web Worker Powered
        </Badge>
      </div>

      <Separator />

      {/* Quick Actions */}
      <div className="grid gap-4 sm:grid-cols-3">
        <Link href="/encrypt" className="group">
          <Card className="transition-colors hover:border-foreground/20 group-hover:shadow-sm h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-3">
                <div className="rounded-md bg-primary/10 p-2">
                  <Lock className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <CardTitle className="text-base">Encrypt File</CardTitle>
                  <CardDescription className="text-xs">
                    Protect with password
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <span className="text-xs text-muted-foreground flex items-center gap-1 group-hover:text-foreground transition-colors">
                Get started <ArrowRight className="h-3 w-3" />
              </span>
            </CardContent>
          </Card>
        </Link>

        <Link href="/decrypt" className="group">
          <Card className="transition-colors hover:border-foreground/20 group-hover:shadow-sm h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-3">
                <div className="rounded-md bg-primary/10 p-2">
                  <Unlock className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <CardTitle className="text-base">Decrypt File</CardTitle>
                  <CardDescription className="text-xs">
                    Unlock your data
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <span className="text-xs text-muted-foreground flex items-center gap-1 group-hover:text-foreground transition-colors">
                Get started <ArrowRight className="h-3 w-3" />
              </span>
            </CardContent>
          </Card>
        </Link>

        <Link href="/text" className="group">
          <Card className="transition-colors hover:border-foreground/20 group-hover:shadow-sm h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center gap-3">
                <div className="rounded-md bg-primary/10 p-2">
                  <Type className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <CardTitle className="text-base">Text Crypto</CardTitle>
                  <CardDescription className="text-xs">
                    Encrypt & decrypt text
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <span className="text-xs text-muted-foreground flex items-center gap-1 group-hover:text-foreground transition-colors">
                Get started <ArrowRight className="h-3 w-3" />
              </span>
            </CardContent>
          </Card>
        </Link>
      </div>

      <Separator />

      {/* System Capability */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold tracking-tight">
            System Capability
          </h2>
          {limits && (
            <Badge variant="outline" className={tierColor}>
              <Gauge className="mr-1 h-3 w-3" />
              {limits.tierLabel} Tier
            </Badge>
          )}
        </div>

        {caps && limits ? (
          <div className="grid gap-4 sm:grid-cols-2">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Hardware
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-sm">
                    <Cpu className="h-4 w-4 text-muted-foreground" />
                    CPU Cores
                  </span>
                  <span className="font-mono text-sm">{caps.cpuCores}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-sm">
                    <MemoryStick className="h-4 w-4 text-muted-foreground" />
                    Approx RAM
                  </span>
                  <span className="font-mono text-sm">
                    {caps.ramGB !== null ? `${caps.ramGB} GB` : "Unknown"}
                  </span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-sm">
                    <Globe className="h-4 w-4 text-muted-foreground" />
                    Browser
                  </span>
                  <span className="font-mono text-sm">{caps.browser}</span>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-sm">
                    <Cog className="h-4 w-4 text-muted-foreground" />
                    Platform
                  </span>
                  <span className="font-mono text-sm">{caps.platform}</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Features & Limits
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-sm">
                    <ShieldCheck className="h-4 w-4 text-muted-foreground" />
                    Web Crypto
                  </span>
                  <Badge
                    variant={
                      caps.webCryptoAvailable ? "secondary" : "destructive"
                    }
                    className="text-xs"
                  >
                    {caps.webCryptoAvailable ? "Available" : "Unavailable"}
                  </Badge>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-sm">
                    <Cog className="h-4 w-4 text-muted-foreground" />
                    Web Workers
                  </span>
                  <Badge
                    variant={
                      caps.webWorkersAvailable ? "secondary" : "destructive"
                    }
                    className="text-xs"
                  >
                    {caps.webWorkersAvailable ? "Available" : "Unavailable"}
                  </Badge>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-sm">
                    <Database className="h-4 w-4 text-muted-foreground" />
                    IndexedDB
                  </span>
                  <Badge
                    variant={
                      caps.indexedDBAvailable ? "secondary" : "destructive"
                    }
                    className="text-xs"
                  >
                    {caps.indexedDBAvailable ? "Available" : "Unavailable"}
                  </Badge>
                </div>
                <Separator />
                <div className="flex items-center justify-between">
                  <span className="text-sm">Max Safe File Size</span>
                  <span className="font-mono text-sm font-semibold">
                    {limits.maxFileSizeMB >= 1024
                      ? `${(limits.maxFileSizeMB / 1024).toFixed(1)} GB`
                      : `${limits.maxFileSizeMB} MB`}
                  </span>
                </div>
              </CardContent>
            </Card>
          </div>
        ) : (
          <Card>
            <CardContent className="py-8 text-center text-muted-foreground">
              Detecting system capabilities...
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
