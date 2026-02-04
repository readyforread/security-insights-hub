import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Calendar, User, Tag } from "lucide-react";
import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { CommentSection } from "@/components/CommentSection";
import { posts, getCvssClass, getCvssSeverity } from "@/data/posts";
import { Button } from "@/components/ui/button";

const Post = () => {
  const { id } = useParams<{ id: string }>();
  const post = posts.find((p) => p.id === id);

  if (!post) {
    return (
      <div className="min-h-screen flex flex-col">
        <Header />
        <main className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <h1 className="text-2xl font-bold mb-4">Пост не найден</h1>
            <Link to="/">
              <Button variant="outline">
                <ArrowLeft className="mr-2 h-4 w-4" />
                Вернуться на главную
              </Button>
            </Link>
          </div>
        </main>
        <Footer />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Header />

      <main className="flex-1">
        {/* Hero Image */}
        <div className="relative h-64 md:h-96">
          <img
            src={post.image}
            alt={post.title}
            className="w-full h-full object-cover"
          />
          <div className="absolute inset-0 bg-gradient-to-t from-background via-background/50 to-transparent" />
        </div>

        <article className="container max-w-3xl -mt-32 relative pb-16">
          {/* Back Button */}
          <Link to="/" className="inline-block mb-6">
            <Button variant="ghost" className="font-mono text-muted-foreground hover:text-primary">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Назад
            </Button>
          </Link>

          {/* Post Header */}
          <div className="cyber-card p-6 md:p-8 space-y-6">
            <div className="flex flex-wrap items-center gap-3">
              <span
                className={`${getCvssClass(post.cvss)} px-3 py-1 rounded font-mono text-xs font-bold`}
              >
                CVSS {post.cvss.toFixed(1)} • {getCvssSeverity(post.cvss)}
              </span>
              {post.cve && (
                <span className="px-3 py-1 rounded bg-secondary font-mono text-xs">
                  {post.cve}
                </span>
              )}
            </div>

            <h1 className="text-2xl md:text-3xl lg:text-4xl font-bold leading-tight">
              {post.title}
            </h1>

            <div className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground font-mono">
              <span className="flex items-center gap-1">
                <User className="h-4 w-4" />
                {post.author}
              </span>
              <span className="flex items-center gap-1">
                <Calendar className="h-4 w-4" />
                {new Date(post.date).toLocaleDateString("ru-RU")}
              </span>
            </div>

            <div className="flex flex-wrap gap-2">
              {post.tags.map((tag) => (
                <span
                  key={tag}
                  className="flex items-center gap-1 px-2 py-1 bg-secondary rounded text-xs font-mono text-muted-foreground"
                >
                  <Tag className="h-3 w-3" />
                  {tag}
                </span>
              ))}
            </div>

            {/* Post Content */}
            <div className="prose prose-invert prose-cyan max-w-none pt-6 border-t border-border">
              {post.content.split("\n\n").map((paragraph, index) => {
                if (paragraph.startsWith("## ")) {
                  return (
                    <h2 key={index} className="text-xl font-bold mt-8 mb-4 text-foreground">
                      {paragraph.replace("## ", "")}
                    </h2>
                  );
                }
                if (paragraph.startsWith("### ")) {
                  return (
                    <h3 key={index} className="text-lg font-bold mt-6 mb-3 text-foreground">
                      {paragraph.replace("### ", "")}
                    </h3>
                  );
                }
                if (paragraph.startsWith("#### ")) {
                  return (
                    <h4 key={index} className="text-base font-bold mt-4 mb-2 text-foreground">
                      {paragraph.replace("#### ", "")}
                    </h4>
                  );
                }
                if (paragraph.startsWith("```")) {
                  const code = paragraph.replace(/```\w*\n?/g, "").trim();
                  return (
                    <pre
                      key={index}
                      className="bg-secondary p-4 rounded-lg overflow-x-auto font-mono text-sm my-4"
                    >
                      <code>{code}</code>
                    </pre>
                  );
                }
                if (paragraph.startsWith("- ") || paragraph.startsWith("1. ")) {
                  const items = paragraph.split("\n");
                  const isOrdered = paragraph.startsWith("1. ");
                  const ListTag = isOrdered ? "ol" : "ul";
                  return (
                    <ListTag key={index} className={`my-4 pl-6 space-y-2 ${isOrdered ? "list-decimal" : "list-disc"}`}>
                      {items.map((item, i) => (
                        <li key={i} className="text-foreground/90">
                          {item.replace(/^[-\d.]+\s*\*?\*?/, "").replace(/\*\*$/, "")}
                        </li>
                      ))}
                    </ListTag>
                  );
                }
                return (
                  <p key={index} className="text-foreground/90 leading-relaxed my-4">
                    {paragraph}
                  </p>
                );
              })}
            </div>

            {/* Comments */}
            <CommentSection postId={post.id} />
          </div>
        </article>
      </main>

      <Footer />
    </div>
  );
};

export default Post;
