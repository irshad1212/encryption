"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "next-themes";
import { useState, useEffect } from "react";
import {
    Shield,
    Lock,
    Unlock,
    Type,
    Menu,
    Sun,
    Moon,
    Monitor,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetTrigger, SheetTitle } from "@/components/ui/sheet";
import { Separator } from "@/components/ui/separator";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";

const navItems = [
    { href: "/", label: "Dashboard", icon: Shield },
    { href: "/encrypt", label: "Encrypt", icon: Lock },
    { href: "/decrypt", label: "Decrypt", icon: Unlock },
    { href: "/text", label: "Text", icon: Type },
];

function NavLinks({ onClick }: { onClick?: () => void }) {
    const pathname = usePathname();

    return (
        <nav className="flex flex-col gap-1">
            {navItems.map((item) => {
                const isActive = pathname === item.href;
                return (
                    <Link key={item.href} href={item.href} onClick={onClick}>
                        <span
                            className={cn(
                                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                                isActive
                                    ? "bg-accent text-accent-foreground"
                                    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                            )}
                        >
                            <item.icon className="h-4 w-4" />
                            {item.label}
                        </span>
                    </Link>
                );
            })}
        </nav>
    );
}

function ThemeToggle() {
    const { setTheme } = useTheme();

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="h-8 w-8">
                    <Sun className="h-4 w-4 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
                    <Moon className="absolute h-4 w-4 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
                    <span className="sr-only">Toggle theme</span>
                </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => setTheme("light")}>
                    <Sun className="mr-2 h-4 w-4" />
                    Light
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setTheme("dark")}>
                    <Moon className="mr-2 h-4 w-4" />
                    Dark
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setTheme("system")}>
                    <Monitor className="mr-2 h-4 w-4" />
                    System
                </DropdownMenuItem>
            </DropdownMenuContent>
        </DropdownMenu>
    );
}

export function AppShell({ children }: { children: React.ReactNode }) {
    const [open, setOpen] = useState(false);
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);
    }, []);

    return (
        <div className="flex min-h-screen">
            {/* Desktop Sidebar */}
            <aside className="hidden lg:flex lg:w-64 lg:flex-col border-r border-border bg-card">
                <div className="flex h-14 items-center px-6 border-b border-border">
                    <Link href="/" className="flex items-center gap-2">
                        <Shield className="h-5 w-5" />
                        <span className="font-semibold tracking-tight">Encryption</span>
                    </Link>
                </div>
                <div className="flex-1 px-3 py-4">
                    <NavLinks />
                </div>
                <div className="border-t border-border px-3 py-3">
                    <div className="flex items-center justify-between px-3">
                        <span className="text-xs text-muted-foreground">
                            Zero-Knowledge
                        </span>
                        {mounted && <ThemeToggle />}
                    </div>
                </div>
            </aside>

            {/* Main content area */}
            <div className="flex flex-1 flex-col">
                {/* Mobile Header */}
                <header className="flex h-14 items-center gap-4 border-b border-border bg-card px-4 lg:px-6">
                    <Sheet open={open} onOpenChange={setOpen}>
                        <SheetTrigger asChild>
                            <Button variant="ghost" size="icon" className="lg:hidden h-8 w-8">
                                <Menu className="h-5 w-5" />
                                <span className="sr-only">Toggle navigation</span>
                            </Button>
                        </SheetTrigger>
                        <SheetContent side="left" className="w-64 p-0">
                            <SheetTitle className="sr-only">Navigation</SheetTitle>
                            <div className="flex h-14 items-center px-6 border-b border-border">
                                <Link
                                    href="/"
                                    className="flex items-center gap-2"
                                    onClick={() => setOpen(false)}
                                >
                                    <Shield className="h-5 w-5" />
                                    <span className="font-semibold tracking-tight">
                                        Encryption
                                    </span>
                                </Link>
                            </div>
                            <div className="px-3 py-4">
                                <NavLinks onClick={() => setOpen(false)} />
                            </div>
                        </SheetContent>
                    </Sheet>

                    <div className="flex items-center gap-2 lg:hidden">
                        <Shield className="h-5 w-5" />
                        <span className="font-semibold tracking-tight">Encryption</span>
                    </div>

                    <div className="ml-auto flex items-center gap-2">
                        {mounted && <div className="lg:hidden"><ThemeToggle /></div>}
                    </div>
                </header>

                {/* Page content */}
                <main className="flex-1 overflow-auto">
                    <div className="mx-auto max-w-5xl px-4 py-8 lg:px-8">{children}</div>
                </main>
            </div>
        </div>
    );
}
