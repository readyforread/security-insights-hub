import { Link } from "react-router-dom";
import { ArrowRight, Calendar, Tag } from "lucide-react";
import { Post, getCvssClass, getCvssSeverity } from "@/data/posts";
import { Button } from "@/components/ui/button";

interface PostCardProps {
  post: Post;
}

export function PostCard({ post }: PostCardProps) {
  return (
    <article className="cyber-card group overflow-hidden transition-all duration-300 hover:border-primary/50 hover:cyber-glow">
      <div className="relative overflow-hidden">
        <img
          src={post.image}
          alt={post.title}
          className="w-full h-48 object-cover transition-transform duration-500 group-hover:scale-105"
        />
        <div className="absolute top-3 right-3">
          <span
            className={`${getCvssClass(post.cvss)} px-3 py-1 rounded font-mono text-xs font-bold`}
          >
            CVSS {post.cvss.toFixed(1)} • {getCvssSeverity(post.cvss)}
          </span>
        </div>
        <div className="absolute inset-0 bg-gradient-to-t from-card to-transparent" />
      </div>

      <div className="p-5 space-y-4">
        <div className="flex items-center gap-4 text-xs text-muted-foreground font-mono">
          <span className="flex items-center gap-1">
            <Calendar className="h-3 w-3" />
            {new Date(post.date).toLocaleDateString("ru-RU")}
          </span>
          {post.cve && (
            <span className="text-primary">{post.cve}</span>
          )}
        </div>

        <h2 className="text-lg font-bold leading-tight group-hover:text-primary transition-colors">
          {post.title}
        </h2>

        <p className="text-sm text-muted-foreground line-clamp-2">
          {post.excerpt}
        </p>

        <div className="flex flex-wrap gap-2">
          {post.tags.slice(0, 3).map((tag) => (
            <span
              key={tag}
              className="flex items-center gap-1 px-2 py-0.5 bg-secondary rounded text-xs font-mono text-muted-foreground"
            >
              <Tag className="h-2.5 w-2.5" />
              {tag}
            </span>
          ))}
        </div>

        <Link to={`/post/${post.id}`}>
          <Button variant="ghost" className="group/btn p-0 h-auto font-mono text-primary hover:text-primary hover:bg-transparent">
            Читать далее
            <ArrowRight className="ml-2 h-4 w-4 transition-transform group-hover/btn:translate-x-1" />
          </Button>
        </Link>
      </div>
    </article>
  );
}
