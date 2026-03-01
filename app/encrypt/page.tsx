"use client";

import { useState, useRef, useCallback, useEffect } from "react";
import {
    Lock,
    Upload,
    Download,
    Eye,
    EyeOff,
    AlertTriangle,
    FileIcon,
    X,
    Settings2,
    RefreshCw,
    Copy,
    Check,
    Wand2,
    Zap,
    Shield,
    ShieldCheck,
    Fingerprint,
    BookOpen,
    XCircle,
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
import { Separator } from "@/components/ui/separator";
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
    type CryptoConfig,
    DEFAULT_CONFIG,
    ARGON2_MEMORY_PRESETS,
    ARGON2_PASSES_MIN,
    ARGON2_PASSES_MAX,
    type PasswordGenConfig,
    DEFAULT_PASSWORD_CONFIG,
    generatePassword,
    estimateGeneratorEntropy,
    getEntropyLabel,
    estimateCrackTime,
    validatePassword,
} from "@/lib/crypto-config";
import { generatePassphrase, passphraseEntropy } from "@/lib/diceware";
import {
    isWebAuthnAvailable,
    isPlatformAuthenticatorAvailable,
    registerCredential,
    getCredentialSecret,
    combineWithPassword,
    hasCredentials,
} from "@/lib/webauthn";
import {
    getSystemCapabilities,
    calculateSystemLimits,
    formatFileSize,
} from "@/lib/system";

type Stage = "idle" | "deriving-key" | "encrypting" | "done" | "error";

export default function EncryptPage() {
    const [file, setFile] = useState<File | null>(null);
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [stage, setStage] = useState<Stage>("idle");
    const [progress, setProgress] = useState(0);
    const [statusMsg, setStatusMsg] = useState("");
    const [error, setError] = useState("");
    const [isDragging, setIsDragging] = useState(false);
    const [maxFileSize, setMaxFileSize] = useState(256 * 1024 * 1024);
    const [maxFileSizeLabel, setMaxFileSizeLabel] = useState("256 MB");
    const fileInputRef = useRef<HTMLInputElement>(null);
    const workerRef = useRef<Worker | null>(null);

    // Advanced config
    const [configDialogOpen, setConfigDialogOpen] = useState(false);
    const [config, setConfig] = useState<CryptoConfig>({ ...DEFAULT_CONFIG });

    // Password generator dialog
    const [genDialogOpen, setGenDialogOpen] = useState(false);
    const [genConfig, setGenConfig] = useState<PasswordGenConfig>({ ...DEFAULT_PASSWORD_CONFIG });
    const [genPassword, setGenPassword] = useState("");
    const [genCopied, setGenCopied] = useState(false);

    // Diceware
    const [dicewareWords, setDicewareWords] = useState(6);
    const [dicewareResult, setDicewareResult] = useState("");
    const [dicewareCopied, setDicewareCopied] = useState(false);

    // WebAuthn
    const [webauthnEnabled, setWebauthnEnabled] = useState(false);
    const [webauthnAvailable, setWebauthnAvailable] = useState(false);
    const [webauthnHasCreds, setWebauthnHasCreds] = useState(false);
    const [webauthnStatus, setWebauthnStatus] = useState("");

    const passwordValidation = validatePassword(password);
    const genEntropy = estimateGeneratorEntropy(genConfig);
    const genEntropyInfo = getEntropyLabel(genEntropy);
    const genCrackTime = estimateCrackTime(genEntropy);
    const dicewareEntropyBits = passphraseEntropy(dicewareWords);

    useEffect(() => {
        const caps = getSystemCapabilities();
        const limits = calculateSystemLimits(caps);
        setMaxFileSize(limits.maxFileSizeBytes);
        setMaxFileSizeLabel(
            limits.maxFileSizeMB >= 1024
                ? `${(limits.maxFileSizeMB / 1024).toFixed(1)} GB`
                : `${limits.maxFileSizeMB} MB`
        );
        if (isWebAuthnAvailable()) {
            setWebauthnAvailable(true);
            isPlatformAuthenticatorAvailable().then((ok) => {
                if (ok) hasCredentials().then(setWebauthnHasCreds);
            });
        }
    }, []);

    const handleFile = useCallback(
        (f: File) => {
            setError("");
            if (f.size > maxFileSize) {
                setError(`File exceeds safe limit for your device (${maxFileSizeLabel}).`);
                return;
            }
            setFile(f);
            setStage("idle");
            setProgress(0);
            setStatusMsg("");
        },
        [maxFileSize, maxFileSizeLabel]
    );

    const handleDrop = useCallback(
        (e: React.DragEvent) => {
            e.preventDefault();
            setIsDragging(false);
            const droppedFile = e.dataTransfer.files[0];
            if (droppedFile) handleFile(droppedFile);
        },
        [handleFile]
    );

    const handleGeneratePassword = () => setGenPassword(generatePassword(genConfig));
    const handleGeneratePassphrase = () => setDicewareResult(generatePassphrase(dicewareWords).passphrase);
    const handleUseGenerated = (pw: string) => { setPassword(pw); setGenDialogOpen(false); };
    const handleCopy = async (text: string, setter: (v: boolean) => void) => {
        await navigator.clipboard.writeText(text);
        setter(true);
        setTimeout(() => setter(false), 2000);
    };

    const handleRegisterWebAuthn = async () => {
        try {
            setWebauthnStatus("Registering hardware key...");
            await registerCredential("Encryption Key");
            setWebauthnHasCreds(true);
            setWebauthnStatus("✓ Hardware key registered");
        } catch (err) {
            setWebauthnStatus(`✗ ${err instanceof Error ? err.message : "Failed"}`);
        }
    };

    const handleEncrypt = async () => {
        if (!file || !password) return;
        if (!passwordValidation.valid) {
            setError("Password does not meet security requirements");
            return;
        }

        setStage("deriving-key");
        setProgress(0);
        setError("");

        try {
            let effectivePassword = password;
            if (webauthnEnabled && webauthnHasCreds) {
                setStatusMsg("Authenticating with hardware key...");
                const secret = await getCredentialSecret();
                effectivePassword = await combineWithPassword(password, secret);
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
                        const blob = new Blob([result], { type: "application/octet-stream" });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url;
                        a.download = `${file.name}.enc.blob`;
                        a.click();
                        URL.revokeObjectURL(url);
                        worker.terminate();
                        setTimeout(() => setPassword(""), 0);
                    }
                };

                worker.onerror = (err) => { setStage("error"); setError(err.message || "Encryption failed"); worker.terminate(); };
                worker.postMessage(
                    { type: "encrypt-file", data: arrayBuffer, password: effectivePassword, id: Date.now().toString(), config },
                    [arrayBuffer]
                );
            } else {
                const { encryptData } = await import("@/lib/crypto");
                const result = await encryptData(arrayBuffer, effectivePassword, config, (p) => {
                    setStage(p.stage as Stage);
                    setProgress(p.progress);
                    setStatusMsg(p.message);
                });
                const blob = new Blob([result], { type: "application/octet-stream" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `${file.name}.enc.blob`;
                a.click();
                URL.revokeObjectURL(url);
                setTimeout(() => setPassword(""), 0);
            }
        } catch (err) {
            setStage("error");
            setError(err instanceof Error ? err.message : "Encryption failed");
        }
    };

    const reset = () => {
        setFile(null);
        setPassword("");
        setStage("idle");
        setProgress(0);
        setStatusMsg("");
        setError("");
        workerRef.current?.terminate();
    };

    return (
        <div className="space-y-6">
            <div className="space-y-1">
                <h1 className="text-2xl font-bold tracking-tight">Encrypt File</h1>
                <p className="text-sm text-muted-foreground">
                    AES-256-GCM with Argon2id WASM KDF · Chunked encryption · AAD-verified
                </p>
            </div>

            {/* Security Info */}
            <div className="grid gap-3 sm:grid-cols-2">
                <Alert>
                    <ShieldCheck className="h-4 w-4" />
                    <AlertDescription className="text-xs">
                        <strong>AES-256-GCM + SHA-512.</strong> Only the strongest algorithm and hash. No weak options.
                    </AlertDescription>
                </Alert>
                <Alert>
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription className="text-xs">
                        <strong>No password recovery.</strong> If you lose your password, your data is gone permanently.
                    </AlertDescription>
                </Alert>
            </div>

            {/* File Selection */}
            <Card>
                <CardHeader>
                    <CardTitle className="text-base">File Selection</CardTitle>
                    <CardDescription className="text-xs">Max safe file size: {maxFileSizeLabel}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div
                        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                        onDragLeave={() => setIsDragging(false)}
                        onDrop={handleDrop}
                        onClick={() => fileInputRef.current?.click()}
                        className={`relative flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed p-8 transition-colors ${isDragging ? "border-primary bg-primary/5" : "border-border hover:border-primary/50 hover:bg-accent/50"
                            }`}
                    >
                        <Upload className="mb-3 h-8 w-8 text-muted-foreground" />
                        <p className="text-sm font-medium">{file ? file.name : "Drop file here or click to browse"}</p>
                        {file ? (
                            <p className="mt-1 text-xs text-muted-foreground">{formatFileSize(file.size)}</p>
                        ) : (
                            <p className="mt-1 text-xs text-muted-foreground">Any file type supported</p>
                        )}
                        <input ref={fileInputRef} type="file" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
                    </div>
                    {file && (
                        <div className="flex items-center gap-3 rounded-md border border-border bg-card p-3">
                            <FileIcon className="h-5 w-5 text-muted-foreground" />
                            <div className="flex-1 min-w-0">
                                <p className="truncate text-sm font-medium">{file.name}</p>
                                <p className="text-xs text-muted-foreground">{formatFileSize(file.size)}</p>
                            </div>
                            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={(e) => { e.stopPropagation(); reset(); }}>
                                <X className="h-4 w-4" />
                            </Button>
                        </div>
                    )}
                </CardContent>
            </Card>

            {/* Password */}
            <Card>
                <CardHeader>
                    <CardTitle className="text-base">Password</CardTitle>
                    <CardDescription className="text-xs">Minimum 16 characters with ≥80 bits entropy</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="space-y-2">
                        <Label htmlFor="password">Password</Label>
                        <div className="relative">
                            <Input
                                id="password"
                                type={showPassword ? "text" : "password"}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="Minimum 16 characters, mix of types"
                                className="pr-10"
                            />
                            <Button type="button" variant="ghost" size="icon" className="absolute right-0 top-0 h-full px-3" onClick={() => setShowPassword(!showPassword)}>
                                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                            </Button>
                        </div>
                    </div>

                    {/* Password validation feedback */}
                    {password.length > 0 && (
                        <div className="space-y-2">
                            <div className="flex items-center justify-between">
                                <span className="text-xs text-muted-foreground">
                                    Strength · {passwordValidation.entropy} bits
                                </span>
                                <span className="text-xs font-medium">{passwordValidation.strength.label}</span>
                            </div>
                            <Progress value={passwordValidation.strength.score} className="h-1.5" />
                            {!passwordValidation.valid && (
                                <div className="space-y-1">
                                    {passwordValidation.errors.map((err, i) => (
                                        <div key={i} className="flex items-start gap-1.5 text-xs text-destructive">
                                            <XCircle className="h-3 w-3 mt-0.5 shrink-0" />
                                            <span>{err}</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                            {passwordValidation.valid && (
                                <div className="flex items-center gap-1.5 text-xs text-emerald-600">
                                    <ShieldCheck className="h-3 w-3" />
                                    <span>Password meets security requirements</span>
                                </div>
                            )}
                        </div>
                    )}

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
                                            <Button variant="outline" size="icon" className="h-9 w-9 shrink-0" onClick={() => handleCopy(genPassword, setGenCopied)}>
                                                {genCopied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                                            </Button>
                                            <Button variant="default" size="sm" className="shrink-0 text-xs" onClick={() => handleUseGenerated(genPassword)}>Use</Button>
                                        </div>
                                    )}
                                    <div className="space-y-2">
                                        <div className="flex items-center justify-between">
                                            <Label className="text-xs">Length</Label>
                                            <span className="font-mono text-xs text-muted-foreground">{genConfig.length}</span>
                                        </div>
                                        <Slider value={[genConfig.length]} onValueChange={([v]) => setGenConfig({ ...genConfig, length: v })} min={16} max={128} step={1} />
                                    </div>
                                    <div className="grid grid-cols-2 gap-3">
                                        <div className="flex items-center justify-between"><Label className="text-xs">Uppercase</Label><Switch checked={genConfig.uppercase} onCheckedChange={(v) => setGenConfig({ ...genConfig, uppercase: v })} /></div>
                                        <div className="flex items-center justify-between"><Label className="text-xs">Lowercase</Label><Switch checked={genConfig.lowercase} onCheckedChange={(v) => setGenConfig({ ...genConfig, lowercase: v })} /></div>
                                        <div className="flex items-center justify-between"><Label className="text-xs">Numbers</Label><Switch checked={genConfig.numbers} onCheckedChange={(v) => setGenConfig({ ...genConfig, numbers: v })} /></div>
                                        <div className="flex items-center justify-between"><Label className="text-xs">Symbols</Label><Switch checked={genConfig.symbols} onCheckedChange={(v) => setGenConfig({ ...genConfig, symbols: v })} /></div>
                                    </div>
                                    <div className="flex items-center justify-between rounded-md bg-muted px-3 py-2">
                                        <div><p className="text-xs font-medium">Entropy: {genEntropy} bits</p><p className="text-xs text-muted-foreground">Crack: ~{genCrackTime}</p></div>
                                        <Badge variant="outline" className={`text-xs ${genEntropyInfo.color}`}><Zap className="mr-1 h-3 w-3" />{genEntropyInfo.label}</Badge>
                                    </div>
                                    <Button onClick={handleGeneratePassword} className="w-full gap-2 text-xs" size="sm"><RefreshCw className="h-3.5 w-3.5" />Generate Password</Button>
                                </TabsContent>

                                <TabsContent value="diceware" className="space-y-5 mt-4">
                                    {dicewareResult && (
                                        <div className="flex items-center gap-2">
                                            <Input value={dicewareResult} readOnly className="font-mono text-xs flex-1 bg-muted" />
                                            <Button variant="outline" size="icon" className="h-9 w-9 shrink-0" onClick={() => handleCopy(dicewareResult, setDicewareCopied)}>
                                                {dicewareCopied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                                            </Button>
                                            <Button variant="default" size="sm" className="shrink-0 text-xs" onClick={() => handleUseGenerated(dicewareResult)}>Use</Button>
                                        </div>
                                    )}
                                    <div className="space-y-2">
                                        <div className="flex items-center justify-between">
                                            <Label className="text-xs">Word Count</Label>
                                            <span className="font-mono text-xs text-muted-foreground">{dicewareWords} words</span>
                                        </div>
                                        <Slider value={[dicewareWords]} onValueChange={([v]) => setDicewareWords(v)} min={5} max={12} step={1} />
                                    </div>
                                    <div className="flex items-center justify-between rounded-md bg-muted px-3 py-2">
                                        <div><p className="text-xs font-medium">Entropy: ~{dicewareEntropyBits} bits</p><p className="text-xs text-muted-foreground">Easy to type/remember</p></div>
                                        <Badge variant="outline" className={`text-xs ${getEntropyLabel(dicewareEntropyBits).color}`}><Zap className="mr-1 h-3 w-3" />{getEntropyLabel(dicewareEntropyBits).label}</Badge>
                                    </div>
                                    <Button onClick={handleGeneratePassphrase} className="w-full gap-2 text-xs" size="sm"><BookOpen className="h-3.5 w-3.5" />Generate Passphrase</Button>
                                </TabsContent>
                            </Tabs>
                        </DialogContent>
                    </Dialog>
                </CardContent>
            </Card>

            {/* WebAuthn Second Factor */}
            {webauthnAvailable && (
                <Card>
                    <CardHeader>
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <Fingerprint className="h-4 w-4 text-muted-foreground" />
                                <CardTitle className="text-base">Hardware 2nd Factor</CardTitle>
                            </div>
                            <Switch checked={webauthnEnabled} onCheckedChange={setWebauthnEnabled} />
                        </div>
                        <CardDescription className="text-xs">
                            Optional: combine password with a hardware key to resist offline brute-force
                        </CardDescription>
                    </CardHeader>
                    {webauthnEnabled && (
                        <CardContent className="space-y-3">
                            {!webauthnHasCreds ? (
                                <Button variant="outline" size="sm" className="w-full text-xs gap-2" onClick={handleRegisterWebAuthn}>
                                    <Fingerprint className="h-3.5 w-3.5" />Register Hardware Key
                                </Button>
                            ) : (
                                <div className="flex items-center gap-1.5 text-xs text-emerald-600">
                                    <ShieldCheck className="h-3 w-3" /><span>Hardware key registered — will be used during encryption</span>
                                </div>
                            )}
                            {webauthnStatus && <p className="text-xs text-muted-foreground">{webauthnStatus}</p>}
                        </CardContent>
                    )}
                </Card>
            )}

            {/* Advanced Configuration — summary card with edit dialog */}
            <Card>
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <Settings2 className="h-4 w-4 text-muted-foreground" />
                            <CardTitle className="text-base">Configuration</CardTitle>
                        </div>
                        <Dialog open={configDialogOpen} onOpenChange={setConfigDialogOpen}>
                            <DialogTrigger asChild>
                                <Button variant="outline" size="sm" className="text-xs gap-1.5">
                                    <Settings2 className="h-3.5 w-3.5" />Edit
                                </Button>
                            </DialogTrigger>
                            <DialogContent className="sm:max-w-xl p-8 gap-6">
                                <DialogHeader>
                                    <DialogTitle>Advanced Configuration</DialogTitle>
                                    <DialogDescription>Argon2id KDF parameters (cipher and hash are locked)</DialogDescription>
                                </DialogHeader>
                                <div className="space-y-6">
                                    <Separator />
                                    <div className="grid gap-4 sm:grid-cols-2">
                                        <div className="space-y-1">
                                            <Label className="text-xs font-medium flex items-center gap-1.5"><Shield className="h-3.5 w-3.5" />Cipher</Label>
                                            <div className="flex items-center gap-2 rounded-md border border-border px-3 py-2 bg-muted">
                                                <Lock className="h-3.5 w-3.5 text-muted-foreground" />
                                                <span className="text-xs font-medium">AES-256-GCM</span>
                                                <Badge variant="outline" className="text-xs ml-auto">Locked</Badge>
                                            </div>
                                        </div>
                                        <div className="space-y-1">
                                            <Label className="text-xs font-medium">KDF</Label>
                                            <div className="flex items-center gap-2 rounded-md border border-border px-3 py-2 bg-muted">
                                                <Lock className="h-3.5 w-3.5 text-muted-foreground" />
                                                <span className="text-xs font-medium">Argon2id (WASM)</span>
                                                <Badge variant="outline" className="text-xs ml-auto">Locked</Badge>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="space-y-3">
                                        <div className="flex items-center justify-between">
                                            <Label className="text-xs font-medium">Memory Cost</Label>
                                            <span className="font-mono text-xs text-muted-foreground">{(config.argon2Memory / 1024).toFixed(0)} MiB</span>
                                        </div>
                                        <div className="flex gap-1.5">
                                            {ARGON2_MEMORY_PRESETS.map((p) => (
                                                <Button key={p.value} variant={config.argon2Memory === p.value ? "default" : "outline"} size="sm" className="text-xs flex-1 h-7" onClick={() => setConfig({ ...config, argon2Memory: p.value })}>{p.label}</Button>
                                            ))}
                                        </div>
                                    </div>

                                    <div className="space-y-3">
                                        <div className="flex items-center justify-between">
                                            <Label className="text-xs font-medium">Time Cost (passes)</Label>
                                            <span className="font-mono text-xs text-muted-foreground">{config.argon2Passes}</span>
                                        </div>
                                        <Slider
                                            value={[config.argon2Passes]}
                                            onValueChange={([v]) => setConfig({ ...config, argon2Passes: v })}
                                            min={ARGON2_PASSES_MIN}
                                            max={ARGON2_PASSES_MAX}
                                            step={1}
                                        />
                                    </div>
                                </div>
                            </DialogContent>
                        </Dialog>
                    </div>
                </CardHeader>
                <CardContent>
                    <div className="rounded-md bg-muted px-3 py-2.5">
                        <p className="text-xs font-mono text-muted-foreground">
                            AES-256-GCM · Argon2id {(config.argon2Memory / 1024).toFixed(0)} MiB · {config.argon2Passes} passes · AAD ✓
                        </p>
                    </div>
                </CardContent>
            </Card>

            {error && (
                <Alert variant="destructive">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription className="text-xs">{error}</AlertDescription>
                </Alert>
            )}

            {stage !== "idle" && stage !== "error" && (
                <Card>
                    <CardContent className="py-4">
                        <div className="space-y-3">
                            <div className="flex items-center justify-between">
                                <span className="text-sm font-medium">{statusMsg}</span>
                                <Badge variant="outline" className="capitalize text-xs">{stage.replace("-", " ")}</Badge>
                            </div>
                            <Progress value={progress} className="h-2" />
                        </div>
                    </CardContent>
                </Card>
            )}

            <div className="flex gap-3">
                <Button
                    onClick={handleEncrypt}
                    disabled={!file || !password || !passwordValidation.valid || (stage !== "idle" && stage !== "done")}
                    className="gap-2"
                >
                    <Lock className="h-4 w-4" />
                    {stage === "done" ? "Encrypt Again" : "Encrypt File"}
                </Button>
                {(file || password) && <Button variant="outline" onClick={reset}>Clear</Button>}
            </div>

            {stage === "done" && (
                <Alert>
                    <Download className="h-4 w-4" />
                    <AlertDescription className="text-xs">
                        Encrypted file downloaded as <strong>{file?.name}.enc.blob</strong>. Store it safely along with your password.
                    </AlertDescription>
                </Alert>
            )}
        </div>
    );
}
