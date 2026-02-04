import { useState } from "react";
import { Link } from "react-router-dom";
import { Menu, X, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";

export function Header() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-16 items-center justify-between">
        <Link to="/" className="flex items-center gap-2 group">
          <Shield className="h-8 w-8 text-primary transition-all group-hover:drop-shadow-[0_0_8px_hsl(var(--primary))]" />
          <span className="font-mono text-xl font-bold text-gradient">
            SecureBlog
          </span>
        </Link>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center gap-6">
          <Link
            to="/"
            className="font-mono text-sm text-muted-foreground hover:text-primary transition-colors"
          >
            Главная
          </Link>
          <Link
            to="/about"
            className="font-mono text-sm text-muted-foreground hover:text-primary transition-colors"
          >
            О блоге
          </Link>
        </nav>

        {/* Mobile Menu Button */}
        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
          onClick={() => setIsMenuOpen(!isMenuOpen)}
        >
          {isMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </Button>
      </div>

      {/* Mobile Navigation */}
      {isMenuOpen && (
        <nav className="md:hidden border-t border-border bg-background p-4 space-y-4">
          <Link
            to="/"
            className="block font-mono text-sm text-muted-foreground hover:text-primary transition-colors"
            onClick={() => setIsMenuOpen(false)}
          >
            Главная
          </Link>
          <Link
            to="/about"
            className="block font-mono text-sm text-muted-foreground hover:text-primary transition-colors"
            onClick={() => setIsMenuOpen(false)}
          >
            О блоге
          </Link>
        </nav>
      )}
    </header>
  );
}
