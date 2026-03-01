"use client";

import { useState, useRef, useEffect } from "react";
import {
    Lock,
    Unlock,
    Eye,
    EyeOff,
    Copy,
    Check,
    AlertTriangle,
    Settings2,
    Wand2,
    RefreshCw,
    Zap,
    Shield,
    BookOpen,
    XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
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
import { combineWithPassword } from "@/lib/webauthn";
import { hasBackupKeyFlag } from "@/lib/crypto";

type Stage = "idle" | "deriving-key" | "encrypting" | "decrypting" | "done" | "error";

const AUTO_CLEAR_MS = 30_000;

export default function TextPage() {
    // Encrypt state
    const [plaintext, setPlaintext] = useState("");
    const [encPassword, setEncPassword] = useState("");
    const [showEncPassword, setShowEncPassword] = useState(false);
    const [encOutput, setEncOutput] = useState("");
    const [encStage, setEncStage] = useState<Stage>("idle");
    const [encProgress, setEncProgress] = useState(0);
    const [encError, setEncError] = useState("");
    const [encCopied, setEncCopied] = useState(false);

    // Decrypt state
    const [ciphertext, setCiphertext] = useState("");
    const [decPassword, setDecPassword] = useState("");
    const [showDecPassword, setShowDecPassword] = useState(false);
    const [decOutput, setDecOutput] = useState("");
    const [decStage, setDecStage] = useState<Stage>("idle");
    const [decProgress, setDecProgress] = useState(0);
    const [decError, setDecError] = useState("");
    const [decCopied, setDecCopied] = useState(false);

    // Config
    const [configDialogOpen, setConfigDialogOpen] = useState(false);
    const [config, setConfig] = useState<CryptoConfig>({ ...DEFAULT_CONFIG });

    // Generator dialog
    const [genDialogOpen, setGenDialogOpen] = useState(false);
    const [genConfig, setGenConfig] = useState<PasswordGenConfig>({ ...DEFAULT_PASSWORD_CONFIG });
    const [genPassword, setGenPassword] = useState("");
    const [genCopied, setGenCopied] = useState(false);
    const [genTarget, setGenTarget] = useState<"enc" | "dec">("enc");

    // Diceware
    const [dicewareWords, setDicewareWords] = useState(6);
    const [dicewareResult, setDicewareResult] = useState("");
    const [dicewareCopied, setDicewareCopied] = useState(false);

    // Secret key
    const [secretKeyEnabled, setSecretKeyEnabled] = useState(false);
    const [generatedSecretKey, setGeneratedSecretKey] = useState("");
    const [secretKeyDialogOpen, setSecretKeyDialogOpen] = useState(false);
    const [secretKeyCopied, setSecretKeyCopied] = useState(false);
    const [decSecretKey, setDecSecretKey] = useState("");
    const [decSecretKeyDetected, setDecSecretKeyDetected] = useState(false);

    const encWorkerRef = useRef<Worker | null>(null);
    const decWorkerRef = useRef<Worker | null>(null);
    const autoClearRef = useRef<ReturnType<typeof setTimeout>>(undefined);

    const encValidation = validatePassword(encPassword);
    const genEntropy = estimateGeneratorEntropy(genConfig);
    const genEntropyInfo = getEntropyLabel(genEntropy);
    const genCrackTime = estimateCrackTime(genEntropy);
    const dicewareEntropyBits = passphraseEntropy(dicewareWords);



    // Auto-clear sensitive outputs
    useEffect(() => {
        if (encOutput || decOutput) {
            autoClearRef.current = setTimeout(() => {
                setEncOutput("");
                setDecOutput("");
                setCiphertext("");
                setEncPassword("");
                setDecPassword("");
            }, AUTO_CLEAR_MS);
            return () => clearTimeout(autoClearRef.current);
        }
    }, [encOutput, decOutput]);

    const handleGeneratePassword = () => setGenPassword(generatePassword(genConfig));
    const handleGeneratePassphrase = () => setDicewareResult(generatePassphrase(dicewareWords).passphrase);
    const handleUseGenerated = (pw: string) => {
        if (genTarget === "enc") setEncPassword(pw); else setDecPassword(pw);
        setGenDialogOpen(false);
    };
    const handleCopy = async (text: string, setter: (v: boolean) => void) => {
        await navigator.clipboard.writeText(text);
        setter(true);
        setTimeout(() => setter(false), 2000);
    };



    const handleEncrypt = async () => {
        if (!plaintext || !encPassword) return;
        if (!encValidation.valid) { setEncError("Password does not meet security requirements"); return; }
        setEncStage("deriving-key");
        setEncProgress(0);
        setEncError("");
        setEncOutput("");

        try {
            let effectivePassword = encPassword;
            let secretKey = "";

            if (secretKeyEnabled) {
                const keyBytes = new Uint8Array(32);
                crypto.getRandomValues(keyBytes);
                secretKey = btoa(String.fromCharCode(...keyBytes));
                effectivePassword = await combineWithPassword(encPassword, keyBytes);
                keyBytes.fill(0);
            }

            const encConfig = { ...config, backupKeyFlag: secretKeyEnabled };

            if (typeof Worker !== "undefined") {
                const worker = new Worker(new URL("@/workers/crypto.worker.ts", import.meta.url));
                encWorkerRef.current = worker;
                worker.onmessage = (e) => {
                    const { stage: s, progress: p, result, error: err } = e.data;
                    if (err) { setEncStage("error"); setEncError(err); worker.terminate(); return; }
                    setEncStage(s as Stage);
                    setEncProgress(p);
                    if (s === "done" && result) {
                        setEncOutput(result);
                        worker.terminate();
                        setTimeout(() => setEncPassword(""), 0);
                        if (secretKey) {
                            setGeneratedSecretKey(secretKey);
                            setSecretKeyDialogOpen(true);
                        }
                    }
                };
                worker.onerror = (err) => { setEncStage("error"); setEncError(err.message); worker.terminate(); };
                worker.postMessage({ type: "encrypt-text", data: plaintext, password: effectivePassword, id: Date.now().toString(), config: encConfig });
            } else {
                const { encryptText } = await import("@/lib/crypto");
                const result = await encryptText(plaintext, effectivePassword, encConfig, (p) => { setEncStage(p.stage as Stage); setEncProgress(p.progress); });
                setEncOutput(result);
                setTimeout(() => setEncPassword(""), 0);
                if (secretKey) {
                    setGeneratedSecretKey(secretKey);
                    setSecretKeyDialogOpen(true);
                }
            }
        } catch (err) {
            setEncStage("error");
            setEncError(err instanceof Error ? err.message : "Encryption failed");
        }
    };

    const handleDecrypt = async () => {
        if (!ciphertext || !decPassword) return;
        setDecStage("deriving-key");
        setDecProgress(0);
        setDecError("");
        setDecOutput("");

        try {
            let effectivePassword = decPassword;

            if (decSecretKeyDetected && decSecretKey) {
                const keyBytes = Uint8Array.from(atob(decSecretKey), c => c.charCodeAt(0));
                effectivePassword = await combineWithPassword(decPassword, keyBytes);
                keyBytes.fill(0);
            }

            if (typeof Worker !== "undefined") {
                const worker = new Worker(new URL("@/workers/crypto.worker.ts", import.meta.url));
                decWorkerRef.current = worker;
                worker.onmessage = (e) => {
                    const { stage: s, progress: p, result, error: err } = e.data;
                    if (err) { setDecStage("error"); setDecError(err); worker.terminate(); return; }
                    setDecStage(s as Stage);
                    setDecProgress(p);
                    if (s === "done" && result) { setDecOutput(result); worker.terminate(); setTimeout(() => setDecPassword(""), 0); }
                };
                worker.onerror = (err) => { setDecStage("error"); setDecError(err.message); worker.terminate(); };
                worker.postMessage({ type: "decrypt-text", data: ciphertext, password: effectivePassword, id: Date.now().toString() });
            } else {
                const { decryptText } = await import("@/lib/crypto");
                const result = await decryptText(ciphertext, effectivePassword, (p) => { setDecStage(p.stage as Stage); setDecProgress(p.progress); });
                setDecOutput(result);
                setTimeout(() => setDecPassword(""), 0);
            }
        } catch (err) {
            setDecStage("error");
            setDecError(err instanceof Error ? err.message : "Decryption failed");
        }
    };

    const copyToClipboard = async (text: string, type: "enc" | "dec") => {
        await navigator.clipboard.writeText(text);
        if (type === "enc") { setEncCopied(true); setTimeout(() => setEncCopied(false), 2000); }
        else { setDecCopied(true); setTimeout(() => setDecCopied(false), 2000); }
    };

    // Password generator dialog content (shared for enc/dec)
    const openGenerator = (target: "enc" | "dec") => { setGenTarget(target); setGenDialogOpen(true); };

    return (
        <div className="space-y-6">
            <div className="space-y-1">
                <h1 className="text-2xl font-bold tracking-tight">Text Encryption</h1>
                <p className="text-sm text-muted-foreground">AES-256-GCM + Argon2id · Outputs auto-clear after 30s</p>
            </div>

            <Tabs defaultValue="encrypt" className="w-full">
                <TabsList className="grid w-full grid-cols-2">
                    <TabsTrigger value="encrypt" className="gap-2"><Lock className="h-3.5 w-3.5" />Encrypt</TabsTrigger>
                    <TabsTrigger value="decrypt" className="gap-2"><Unlock className="h-3.5 w-3.5" />Decrypt</TabsTrigger>
                </TabsList>

                {/* ENCRYPT TAB */}
                <TabsContent value="encrypt" className="space-y-4 mt-4">
                    <Card>
                        <CardHeader><CardTitle className="text-base">Plaintext Input</CardTitle></CardHeader>
                        <CardContent className="space-y-4">
                            <Textarea value={plaintext} onChange={(e) => setPlaintext(e.target.value)} placeholder="Type your secret message here..." rows={5} className="font-mono text-sm resize-none" />

                            <div className="space-y-2">
                                <Label htmlFor="enc-password">Password</Label>
                                <div className="relative">
                                    <Input id="enc-password" type={showEncPassword ? "text" : "password"} value={encPassword} onChange={(e) => setEncPassword(e.target.value)} placeholder="Minimum 16 characters" className="pr-10" />
                                    <Button type="button" variant="ghost" size="icon" className="absolute right-0 top-0 h-full px-3" onClick={() => setShowEncPassword(!showEncPassword)}>
                                        {showEncPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                                    </Button>
                                </div>
                            </div>

                            {encPassword.length > 0 && (
                                <div className="space-y-2">
                                    <div className="flex items-center justify-between">
                                        <span className="text-xs text-muted-foreground">{encValidation.entropy} bits</span>
                                        <span className="text-xs font-medium">{encValidation.strength.label}</span>
                                    </div>
                                    <Progress value={encValidation.strength.score} className="h-1.5" />
                                    {!encValidation.valid && encValidation.errors.map((err, i) => (
                                        <div key={i} className="flex items-start gap-1.5 text-xs text-destructive"><XCircle className="h-3 w-3 mt-0.5 shrink-0" /><span>{err}</span></div>
                                    ))}
                                    {encValidation.valid && (
                                        <div className="flex items-center gap-1.5 text-xs text-emerald-600"><Shield className="h-3 w-3" /><span>Meets security requirements</span></div>
                                    )}
                                </div>
                            )}

                            <Button variant="outline" size="sm" className="w-full gap-2 text-xs" onClick={() => openGenerator("enc")}>
                                <Wand2 className="h-3.5 w-3.5" />Password / Passphrase Generator
                            </Button>

                            <Button onClick={handleEncrypt} disabled={!plaintext || !encPassword || !encValidation.valid || (encStage !== "idle" && encStage !== "done" && encStage !== "error")} className="gap-2">
                                <Lock className="h-4 w-4" />Encrypt Text
                            </Button>
                        </CardContent>
                    </Card>

                    {/* Config summary card */}
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
                                            <DialogDescription>Argon2id KDF parameters (cipher is locked)</DialogDescription>
                                        </DialogHeader>
                                        <div className="space-y-6">
                                            <Separator />
                                            <div className="grid gap-4 sm:grid-cols-2">
                                                <div className="space-y-1">
                                                    <Label className="text-xs font-medium flex items-center gap-1.5"><Shield className="h-3.5 w-3.5" />Cipher</Label>
                                                    <div className="flex items-center gap-2 rounded-md border border-border px-3 py-2 bg-muted">
                                                        <Lock className="h-3.5 w-3.5 text-muted-foreground" /><span className="text-xs font-medium">AES-256-GCM</span><Badge variant="outline" className="text-xs ml-auto">Locked</Badge>
                                                    </div>
                                                </div>
                                                <div className="space-y-1">
                                                    <Label className="text-xs font-medium">KDF</Label>
                                                    <div className="flex items-center gap-2 rounded-md border border-border px-3 py-2 bg-muted">
                                                        <Lock className="h-3.5 w-3.5 text-muted-foreground" /><span className="text-xs font-medium">Argon2id (WASM)</span><Badge variant="outline" className="text-xs ml-auto">Locked</Badge>
                                                    </div>
                                                </div>
                                            </div>
                                            <div className="space-y-3">
                                                <div className="flex items-center justify-between"><Label className="text-xs font-medium">Memory Cost</Label><span className="font-mono text-xs text-muted-foreground">{(config.argon2Memory / 1024).toFixed(0)} MiB</span></div>
                                                <div className="flex gap-1.5">
                                                    {ARGON2_MEMORY_PRESETS.map((p) => (
                                                        <Button key={p.value} variant={config.argon2Memory === p.value ? "default" : "outline"} size="sm" className="text-xs flex-1 h-7" onClick={() => setConfig({ ...config, argon2Memory: p.value })}>{p.label}</Button>
                                                    ))}
                                                </div>
                                            </div>
                                            <div className="space-y-3">
                                                <div className="flex items-center justify-between"><Label className="text-xs font-medium">Time Cost (passes)</Label><span className="font-mono text-xs text-muted-foreground">{config.argon2Passes}</span></div>
                                                <Slider value={[config.argon2Passes]} onValueChange={([v]) => setConfig({ ...config, argon2Passes: v })} min={ARGON2_PASSES_MIN} max={ARGON2_PASSES_MAX} step={1} />
                                            </div>
                                        </div>
                                    </DialogContent>
                                </Dialog>
                            </div>
                        </CardHeader>
                        <CardContent>
                            <div className="rounded-md bg-muted px-3 py-2.5">
                                <p className="text-xs font-mono text-muted-foreground">AES-256-GCM · Argon2id {(config.argon2Memory / 1024).toFixed(0)} MiB · {config.argon2Passes} passes · AAD ✓</p>
                            </div>
                        </CardContent>
                    </Card>

                    {encStage !== "idle" && encStage !== "error" && encStage !== "done" && (
                        <Card><CardContent className="py-4"><div className="space-y-3"><div className="flex items-center justify-between"><span className="text-sm font-medium">Processing...</span><Badge variant="outline" className="capitalize text-xs">{encStage.replace("-", " ")}</Badge></div><Progress value={encProgress} className="h-2" /></div></CardContent></Card>
                    )}
                    {encError && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertDescription className="text-xs">{encError}</AlertDescription></Alert>}
                    {encOutput && (
                        <Card>
                            <CardHeader className="pb-2">
                                <div className="flex items-center justify-between">
                                    <CardTitle className="text-base">Encrypted (Base64)</CardTitle>
                                    <div className="flex items-center gap-2">
                                        <Badge variant="outline" className="text-xs">Auto-clears in 30s</Badge>
                                        <Button variant="ghost" size="sm" className="gap-1.5 h-7 text-xs" onClick={() => copyToClipboard(encOutput, "enc")}>
                                            {encCopied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}{encCopied ? "Copied" : "Copy"}
                                        </Button>
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent><Textarea value={encOutput} readOnly rows={4} className="font-mono text-xs resize-none bg-muted" /></CardContent>
                        </Card>
                    )}
                </TabsContent>

                {/* DECRYPT TAB */}
                <TabsContent value="decrypt" className="space-y-4 mt-4">
                    <Card>
                        <CardHeader><CardTitle className="text-base">Encrypted Input</CardTitle><CardDescription className="text-xs">Config auto-detected from blob (AAD-verified)</CardDescription></CardHeader>
                        <CardContent className="space-y-4">
                            <Textarea value={ciphertext} onChange={(e) => setCiphertext(e.target.value)} placeholder="Paste Base64 encrypted text here..." rows={5} className="font-mono text-sm resize-none" />
                            <div className="space-y-2">
                                <Label htmlFor="dec-password">Password</Label>
                                <div className="relative">
                                    <Input id="dec-password" type={showDecPassword ? "text" : "password"} value={decPassword} onChange={(e) => setDecPassword(e.target.value)} placeholder="Enter decryption password" className="pr-10" />
                                    <Button type="button" variant="ghost" size="icon" className="absolute right-0 top-0 h-full px-3" onClick={() => setShowDecPassword(!showDecPassword)}>
                                        {showDecPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                                    </Button>
                                </div>
                            </div>

                            <Button variant="outline" size="sm" className="w-full gap-2 text-xs" onClick={() => openGenerator("dec")}>
                                <Wand2 className="h-3.5 w-3.5" />Password / Passphrase Generator
                            </Button>

                            <Button onClick={handleDecrypt} disabled={!ciphertext || !decPassword || (decStage !== "idle" && decStage !== "done" && decStage !== "error")} className="gap-2">
                                <Unlock className="h-4 w-4" />Decrypt Text
                            </Button>
                        </CardContent>
                    </Card>

                    {decStage !== "idle" && decStage !== "error" && decStage !== "done" && (
                        <Card><CardContent className="py-4"><div className="space-y-3"><div className="flex items-center justify-between"><span className="text-sm font-medium">Processing...</span><Badge variant="outline" className="capitalize text-xs">{decStage.replace("-", " ")}</Badge></div><Progress value={decProgress} className="h-2" /></div></CardContent></Card>
                    )}
                    {decError && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertDescription className="text-xs">{decError}</AlertDescription></Alert>}
                    {decOutput && (
                        <Card>
                            <CardHeader className="pb-2">
                                <div className="flex items-center justify-between">
                                    <CardTitle className="text-base">Decrypted Output</CardTitle>
                                    <div className="flex items-center gap-2">
                                        <Badge variant="outline" className="text-xs">Auto-clears in 30s</Badge>
                                        <Button variant="ghost" size="sm" className="gap-1.5 h-7 text-xs" onClick={() => copyToClipboard(decOutput, "dec")}>
                                            {decCopied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}{decCopied ? "Copied" : "Copy"}
                                        </Button>
                                    </div>
                                </div>
                            </CardHeader>
                            <CardContent><Textarea value={decOutput} readOnly rows={4} className="font-mono text-sm resize-none bg-muted" /></CardContent>
                        </Card>
                    )}
                </TabsContent>
            </Tabs>

            {/* Password Generator Dialog (shared) */}
            <Dialog open={genDialogOpen} onOpenChange={setGenDialogOpen}>
                <DialogContent className="sm:max-w-xl p-8 gap-6">
                    <DialogHeader>
                        <DialogTitle>Generate Password</DialogTitle>
                        <DialogDescription>Create a strong random password or Diceware passphrase</DialogDescription>
                    </DialogHeader>
                    <Tabs defaultValue="password" className="w-full">
                        <TabsList className="grid w-full grid-cols-2 h-8">
                            <TabsTrigger value="password" className="text-xs gap-1"><Lock className="h-3 w-3" />Random</TabsTrigger>
                            <TabsTrigger value="diceware" className="text-xs gap-1"><BookOpen className="h-3 w-3" />Diceware</TabsTrigger>
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

            {/* Secret Key — Second Factor */}
            <Card>
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <Shield className="h-4 w-4 text-muted-foreground" />
                            <CardTitle className="text-base">Secret Key</CardTitle>
                            {secretKeyEnabled && <Badge variant="secondary" className="text-xs">Enabled</Badge>}
                        </div>
                        <Switch
                            checked={secretKeyEnabled}
                            onCheckedChange={setSecretKeyEnabled}
                        />
                    </div>
                    <CardDescription className="text-xs">
                        {secretKeyEnabled
                            ? "A unique secret key will be generated after encryption. You'll need it to decrypt."
                            : "Add a second factor — a generated secret key required alongside your password to decrypt"
                        }
                    </CardDescription>
                </CardHeader>
            </Card>

            {/* Secret Key Display Dialog */}
            <Dialog open={secretKeyDialogOpen} onOpenChange={(open) => {
                if (!open) setGeneratedSecretKey("");
                setSecretKeyDialogOpen(open);
            }}>
                <DialogContent className="sm:max-w-lg">
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <Shield className="h-5 w-5" />
                            Your Secret Key
                        </DialogTitle>
                        <DialogDescription>
                            Save this key securely. You will need it alongside your password to decrypt.
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-2">
                        <div className="flex items-center gap-3 rounded-lg border border-border bg-muted px-4 py-3">
                            <span className="flex-1 font-mono text-sm tracking-widest select-none">
                                {"•".repeat(32)}
                            </span>
                            <Button
                                variant="outline"
                                size="sm"
                                className="shrink-0 h-8 gap-1.5"
                                onClick={() => handleCopy(generatedSecretKey, setSecretKeyCopied)}
                            >
                                {secretKeyCopied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                                {secretKeyCopied ? "Copied" : "Copy"}
                            </Button>
                        </div>
                        <Alert>
                            <AlertTriangle className="h-4 w-4" />
                            <AlertDescription className="text-xs">
                                This key is shown only once. If you lose it, the encrypted text cannot be recovered.
                            </AlertDescription>
                        </Alert>
                    </div>
                    <div className="flex justify-end pt-2">
                        <Button
                            size="sm"
                            onClick={() => {
                                setSecretKeyDialogOpen(false);
                                setGeneratedSecretKey("");
                            }}
                        >
                            I've saved the key
                        </Button>
                    </div>
                </DialogContent>
            </Dialog>

            {/* Secret Key input for decryption — auto-detected */}
            {decSecretKeyDetected && (
                <Card>
                    <CardHeader>
                        <div className="flex items-center gap-2">
                            <Shield className="h-4 w-4 text-muted-foreground" />
                            <CardTitle className="text-base">Secret Key Required</CardTitle>
                            <Badge variant="secondary" className="text-xs">Detected</Badge>
                        </div>
                        <CardDescription className="text-xs">
                            This text was encrypted with a secret key. Paste it below to decrypt.
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <Input
                            type="password"
                            placeholder="Paste your secret key"
                            value={decSecretKey}
                            onChange={(e) => setDecSecretKey(e.target.value)}
                            className="font-mono text-sm"
                        />
                    </CardContent>
                </Card>
            )}

        </div>
    );
}
