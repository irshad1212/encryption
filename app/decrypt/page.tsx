"use client";

import { useState, useRef, useCallback, useEffect } from "react";
import {
    Unlock,
    Upload,
    Download,
    Eye,
    EyeOff,
    AlertTriangle,
    FileIcon,
    X,
    Wand2,
    RefreshCw,
    Copy,
    Check,
    Zap,
    ShieldCheck,
    Shield,
    BookOpen,
    Lock,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";
import {
    formatFileSize,
    getSystemCapabilities,
    calculateSystemLimits,
} from "@/lib/system";
import {
    type PasswordGenConfig,
    DEFAULT_PASSWORD_CONFIG,
    generatePassword,
    estimateGeneratorEntropy,
    getEntropyLabel,
    estimateCrackTime,
} from "@/lib/crypto-config";
import { generatePassphrase, passphraseEntropy } from "@/lib/diceware";
import {
    combineWithPassword,
} from "@/lib/webauthn";
import { hasBackupKeyFlag } from "@/lib/crypto";

type Stage = "idle" | "deriving-key" | "decrypting" | "done" | "error";

export default function DecryptPage() {
    const [file, setFile] = useState<File | null>(null);
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [stage, setStage] = useState<Stage>("idle");
    const [progress, setProgress] = useState(0);
    const [statusMsg, setStatusMsg] = useState("");
    const [error, setError] = useState("");
    const [isDragging, setIsDragging] = useState(false);
    const [decryptedName, setDecryptedName] = useState("");
    const [maxFileSize, setMaxFileSize] = useState(256 * 1024 * 1024);
    const [maxFileSizeLabel, setMaxFileSizeLabel] = useState("256 MB");
    const fileInputRef = useRef<HTMLInputElement>(null);
    const workerRef = useRef<Worker | null>(null);

    // Password generator dialog
    const [genDialogOpen, setGenDialogOpen] = useState(false);
    const [genConfig, setGenConfig] = useState<PasswordGenConfig>({ ...DEFAULT_PASSWORD_CONFIG });
    const [genPassword, setGenPassword] = useState("");
    const [genCopied, setGenCopied] = useState(false);

    // Diceware
    const [dicewareWords, setDicewareWords] = useState(6);
    const [dicewareResult, setDicewareResult] = useState("");
    const [dicewareCopied, setDicewareCopied] = useState(false);

    // Secret key (auto-detected from file header)
    const [backupKeyDetected, setBackupKeyDetected] = useState(false);
    const [backupKey, setBackupKey] = useState("");

    const genEntropy = estimateGeneratorEntropy(genConfig);
    const genEntropyInfo = getEntropyLabel(genEntropy);
    const genCrackTime = estimateCrackTime(genEntropy);
    const dicewareEntropyBits = passphraseEntropy(dicewareWords);

    useEffect(() => {
        const caps = getSystemCapabilities();
        const limits = calculateSystemLimits(caps);
        setMaxFileSize(limits.maxFileSizeBytes);
        setMaxFileSizeLabel(
            limits.maxFileSizeMB >= 1024 ? `${(limits.maxFileSizeMB / 1024).toFixed(1)} GB` : `${limits.maxFileSizeMB} MB`
        );
    }, []);

    const handleFile = useCallback((f: File) => {
        setError("");
        if (f.size > maxFileSize) {
            setError(`File exceeds safe limit for your device (${maxFileSizeLabel}). This may cause your browser to crash.`);
            return;
        }
        setFile(f);
        setStage("idle");
        setProgress(0);
        setStatusMsg("");

        // Auto-detect secret key flag from header byte[2]
        const reader = new FileReader();
        reader.onload = () => {
            const arr = new Uint8Array(reader.result as ArrayBuffer);
            // v4 header: byte[0] = version (4), byte[2] = config byte
            if (arr.length >= 10 && arr[0] === 4) {
                setBackupKeyDetected(hasBackupKeyFlag(arr[2]));
            } else {
                setBackupKeyDetected(false);
            }
        };
        reader.readAsArrayBuffer(f.slice(0, 10));
    }, [maxFileSize, maxFileSizeLabel]);

    const handleDrop = useCallback(
        (e: React.DragEvent) => {
            e.preventDefault();
            setIsDragging(false);
            const droppedFile = e.dataTransfer.files[0];
            if (droppedFile) handleFile(droppedFile);
        },
        [handleFile]
    );

    const getOriginalFilename = (name: string) => {
        if (name.endsWith(".enc.blob")) return name.slice(0, -9);
        if (name.endsWith(".blob")) return name.slice(0, -5);
        return `decrypted_${name}`;
    };

    const handleGeneratePassword = () => setGenPassword(generatePassword(genConfig));
    const handleGeneratePassphrase = () => setDicewareResult(generatePassphrase(dicewareWords).passphrase);
    const handleUseGenerated = (pw: string) => { setPassword(pw); setGenDialogOpen(false); };
    const handleCopy = async (text: string, setter: (v: boolean) => void) => {
        await navigator.clipboard.writeText(text);
        setter(true);
        setTimeout(() => setter(false), 2000);
    };

    const handleDecrypt = async () => {
        if (!file || !password) return;
        setStage("deriving-key");
        setProgress(0);
        setError("");
        const originalName = getOriginalFilename(file.name);
        setDecryptedName(originalName);

        try {
            let effectivePassword = password;
            if (backupKeyDetected && backupKey) {
                const keyBytes = Uint8Array.from(atob(backupKey), c => c.charCodeAt(0));
                effectivePassword = await combineWithPassword(password, keyBytes);
                keyBytes.fill(0);
            }

            const arrayBuffer = await file.arrayBuffer();
            if (typeof Worker !== "undefined") {
                const worker = new Worker(new URL("@/workers/crypto.worker.ts", import.meta.url));
                workerRef.current = worker;
                worker.onmessage = (e) => {
                    const { stage: s, progress: p, message: m, result, error: err } = e.data;
                    if (err) { setStage("error"); setError(err); worker.terminate(); return; }
                    setStage(s as Stage);
                    setProgress(p);
                    setStatusMsg(m);
                    if (s === "done" && result) {
                        const blob = new Blob([result]);
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = originalName;
                        a.click();
                        URL.revokeObjectURL(url);
                        worker.terminate();
                        setTimeout(() => setPassword(""), 0);
                    }
                };
                worker.onerror = (err) => { setStage("error"); setError(err.message || "Decryption failed"); worker.terminate(); };
                worker.postMessage({ type: "decrypt-file", data: arrayBuffer, password: effectivePassword, id: Date.now().toString() }, [arrayBuffer]);
            } else {
                const { decryptData } = await import("@/lib/crypto");
                const result = await decryptData(arrayBuffer, effectivePassword, (p) => {
                    setStage(p.stage as Stage);
                    setProgress(p.progress);
                    setStatusMsg(p.message);
                });
                const blob = new Blob([result]);
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = originalName;
                a.click();
                URL.revokeObjectURL(url);
                setTimeout(() => setPassword(""), 0);
            }
        } catch (err) {
            setStage("error");
            setError(err instanceof Error ? err.message : "Decryption failed");
        }
    };

    const reset = () => {
        setFile(null);
        setPassword("");
        setStage("idle");
        setProgress(0);
        setStatusMsg("");
        setError("");
        setDecryptedName("");
        workerRef.current?.terminate();
    };

    return (
        <div className="space-y-6">
            <div className="space-y-1">
                <h1 className="text-2xl font-bold tracking-tight">Decrypt File</h1>
                <p className="text-sm text-muted-foreground">
                    Upload an encrypted blob — config is auto-detected from the header (AAD-verified)
                </p>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle className="text-base">Encrypted File</CardTitle>
                    <CardDescription className="text-xs">
                        Max safe file size: {maxFileSizeLabel} · Select an .enc.blob file
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div
                        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                        onDragLeave={() => setIsDragging(false)}
                        onDrop={handleDrop}
                        onClick={() => fileInputRef.current?.click()}
                        className={`relative flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed p-8 transition-colors ${isDragging ? "border-primary bg-primary/5" : "border-border hover:border-primary/50 hover:bg-accent/50"}`}
                    >
                        <Upload className="mb-3 h-8 w-8 text-muted-foreground" />
                        <p className="text-sm font-medium">{file ? file.name : "Drop encrypted blob here or click to browse"}</p>
                        {file ? <p className="mt-1 text-xs text-muted-foreground">{formatFileSize(file.size)}</p> : <p className="mt-1 text-xs text-muted-foreground">.enc.blob files</p>}
                        <input ref={fileInputRef} type="file" className="hidden" accept=".blob,.enc.blob" onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
                    </div>
                    {file && (
                        <div className="flex items-center gap-3 rounded-md border border-border bg-card p-3">
                            <FileIcon className="h-5 w-5 text-muted-foreground" />
                            <div className="flex-1 min-w-0"><p className="truncate text-sm font-medium">{file.name}</p><p className="text-xs text-muted-foreground">{formatFileSize(file.size)}</p></div>
                            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={(e) => { e.stopPropagation(); reset(); }}><X className="h-4 w-4" /></Button>
                        </div>
                    )}
                </CardContent>
            </Card>

            <Card>
                <CardHeader>
                    <CardTitle className="text-base">Password</CardTitle>
                    <CardDescription className="text-xs">Enter the password used during encryption</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="space-y-2">
                        <Label htmlFor="decrypt-password">Password</Label>
                        <div className="relative">
                            <Input id="decrypt-password" type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Enter decryption password" className="pr-10" />
                            <Button type="button" variant="ghost" size="icon" className="absolute right-0 top-0 h-full px-3" onClick={() => setShowPassword(!showPassword)}>
                                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                            </Button>
                        </div>
                    </div>

                    {/* Password Generator Dialog */}
                    <Dialog open={genDialogOpen} onOpenChange={setGenDialogOpen}>
                        <DialogTrigger asChild>
                            <Button variant="outline" size="sm" className="w-full gap-2 text-xs">
                                <Wand2 className="h-3.5 w-3.5" />
                                Password / Passphrase Generator
                            </Button>
                        </DialogTrigger>
                        <DialogContent className="sm:max-w-xl p-8 gap-6">
                            <DialogHeader>
                                <DialogTitle>Generate Password</DialogTitle>
                                <DialogDescription>Create a strong random password or Diceware passphrase</DialogDescription>
                            </DialogHeader>
                            <Tabs defaultValue="password" className="w-full">
                                <TabsList className="grid w-full grid-cols-2 h-8">
                                    <TabsTrigger value="password" className="text-xs gap-1"><Lock className="h-3 w-3" />Random Password</TabsTrigger>
                                    <TabsTrigger value="diceware" className="text-xs gap-1"><BookOpen className="h-3 w-3" />Diceware Passphrase</TabsTrigger>
                                </TabsList>
                                <TabsContent value="password" className="space-y-5 mt-4">
                                    {genPassword && (
                                        <div className="flex items-center gap-2">
                                            <Input value={genPassword} readOnly className="font-mono text-xs flex-1 bg-muted" />
                                            <Button variant="outline" size="icon" className="h-9 w-9 shrink-0" onClick={() => handleCopy(genPassword, setGenCopied)}>{genCopied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}</Button>
                                            <Button variant="default" size="sm" className="shrink-0 text-xs" onClick={() => handleUseGenerated(genPassword)}>Use</Button>
                                        </div>
                                    )}
                                    <div className="space-y-2">
                                        <div className="flex items-center justify-between"><Label className="text-xs">Length</Label><span className="font-mono text-xs text-muted-foreground">{genConfig.length}</span></div>
                                        <Slider value={[genConfig.length]} onValueChange={([v]) => setGenConfig({ ...genConfig, length: v })} min={16} max={128} step={1} />
                                    </div>
                                    <div className="grid grid-cols-2 gap-3">
                                        <div className="flex items-center justify-between"><Label className="text-xs">Uppercase</Label><Switch checked={genConfig.uppercase} onCheckedChange={(v) => setGenConfig({ ...genConfig, uppercase: v })} /></div>
                                        <div className="flex items-center justify-between"><Label className="text-xs">Lowercase</Label><Switch checked={genConfig.lowercase} onCheckedChange={(v) => setGenConfig({ ...genConfig, lowercase: v })} /></div>
                                        <div className="flex items-center justify-between"><Label className="text-xs">Numbers</Label><Switch checked={genConfig.numbers} onCheckedChange={(v) => setGenConfig({ ...genConfig, numbers: v })} /></div>
                                        <div className="flex items-center justify-between"><Label className="text-xs">Symbols</Label><Switch checked={genConfig.symbols} onCheckedChange={(v) => setGenConfig({ ...genConfig, symbols: v })} /></div>
                                    </div>
                                    <div className="flex items-center justify-between rounded-md bg-muted px-3 py-2">
                                        <div><p className="text-xs font-medium">{genEntropy} bits</p><p className="text-xs text-muted-foreground">~{genCrackTime}</p></div>
                                        <Badge variant="outline" className={`text-xs ${genEntropyInfo.color}`}><Zap className="mr-1 h-3 w-3" />{genEntropyInfo.label}</Badge>
                                    </div>
                                    <Button onClick={handleGeneratePassword} className="w-full gap-2 text-xs" size="sm"><RefreshCw className="h-3.5 w-3.5" />Generate</Button>
                                </TabsContent>
                                <TabsContent value="diceware" className="space-y-5 mt-4">
                                    {dicewareResult && (
                                        <div className="flex items-center gap-2">
                                            <Input value={dicewareResult} readOnly className="font-mono text-xs flex-1 bg-muted" />
                                            <Button variant="outline" size="icon" className="h-9 w-9 shrink-0" onClick={() => handleCopy(dicewareResult, setDicewareCopied)}>{dicewareCopied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}</Button>
                                            <Button variant="default" size="sm" className="shrink-0 text-xs" onClick={() => handleUseGenerated(dicewareResult)}>Use</Button>
                                        </div>
                                    )}
                                    <div className="space-y-2">
                                        <div className="flex items-center justify-between"><Label className="text-xs">Words</Label><span className="font-mono text-xs text-muted-foreground">{dicewareWords}</span></div>
                                        <Slider value={[dicewareWords]} onValueChange={([v]) => setDicewareWords(v)} min={5} max={12} step={1} />
                                    </div>
                                    <div className="flex items-center justify-between rounded-md bg-muted px-3 py-2">
                                        <p className="text-xs font-medium">~{dicewareEntropyBits} bits</p>
                                        <Badge variant="outline" className={`text-xs ${getEntropyLabel(dicewareEntropyBits).color}`}><Zap className="mr-1 h-3 w-3" />{getEntropyLabel(dicewareEntropyBits).label}</Badge>
                                    </div>
                                    <Button onClick={handleGeneratePassphrase} className="w-full gap-2 text-xs" size="sm"><BookOpen className="h-3.5 w-3.5" />Generate Passphrase</Button>
                                </TabsContent>
                            </Tabs>
                        </DialogContent>
                    </Dialog>
                </CardContent>
            </Card>

            {/* Secret Key — auto-detected from file header */}
            {backupKeyDetected && (
                <Card>
                    <CardHeader>
                        <div className="flex items-center gap-2">
                            <Shield className="h-4 w-4 text-muted-foreground" />
                            <CardTitle className="text-base">Secret Key Required</CardTitle>
                            <Badge variant="secondary" className="text-xs">Detected</Badge>
                        </div>
                        <CardDescription className="text-xs">
                            This file was encrypted with a secret key. Paste it below to decrypt.
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <Input
                            type="password"
                            placeholder="Paste your secret key"
                            value={backupKey}
                            onChange={(e) => setBackupKey(e.target.value)}
                            className="font-mono text-sm"
                        />
                    </CardContent>
                </Card>
            )}

            {error && (
                <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertDescription className="text-xs">{error}</AlertDescription></Alert>
            )}

            {stage !== "idle" && stage !== "error" && (
                <Card>
                    <CardContent className="py-4">
                        <div className="space-y-3">
                            <div className="flex items-center justify-between"><span className="text-sm font-medium">{statusMsg}</span><Badge variant="outline" className="capitalize text-xs">{stage.replace("-", " ")}</Badge></div>
                            <Progress value={progress} className="h-2" />
                        </div>
                    </CardContent>
                </Card>
            )}

            <div className="flex gap-3">
                <Button onClick={handleDecrypt} disabled={!file || !password || (stage !== "idle" && stage !== "done")} className="gap-2"><Unlock className="h-4 w-4" />{stage === "done" ? "Decrypt Again" : "Decrypt File"}</Button>
                {(file || password) && <Button variant="outline" onClick={reset}>Clear</Button>}
            </div>

            {stage === "done" && (
                <Alert><Download className="h-4 w-4" /><AlertDescription className="text-xs">Decrypted file downloaded as <strong>{decryptedName}</strong>.</AlertDescription></Alert>
            )}
        </div>
    );
}
