import { useState } from "react";
import { MessageSquare, Send, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { comments as initialComments, Comment } from "@/data/posts";

interface CommentSectionProps {
  postId: string;
}

export function CommentSection({ postId }: CommentSectionProps) {
  const [comments, setComments] = useState<Comment[]>(
    initialComments.filter((c) => c.postId === postId)
  );
  const [newComment, setNewComment] = useState("");
  const [authorName, setAuthorName] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newComment.trim() || !authorName.trim()) return;

    const comment: Comment = {
      id: Date.now().toString(),
      postId,
      author: authorName,
      content: newComment,
      date: new Date().toISOString().split("T")[0],
    };

    setComments([...comments, comment]);
    setNewComment("");
  };

  return (
    <section className="mt-12 pt-8 border-t border-border">
      <h3 className="flex items-center gap-2 text-xl font-bold mb-6">
        <MessageSquare className="h-5 w-5 text-primary" />
        Комментарии ({comments.length})
      </h3>

      {/* Comment Form */}
      <form onSubmit={handleSubmit} className="mb-8 space-y-4">
        <Input
          placeholder="Ваше имя"
          value={authorName}
          onChange={(e) => setAuthorName(e.target.value)}
          className="bg-secondary border-border focus:border-primary"
        />
        <Textarea
          placeholder="Напишите комментарий..."
          value={newComment}
          onChange={(e) => setNewComment(e.target.value)}
          className="bg-secondary border-border focus:border-primary min-h-[100px]"
        />
        <Button type="submit" className="font-mono">
          <Send className="mr-2 h-4 w-4" />
          Отправить
        </Button>
      </form>

      {/* Comments List */}
      <div className="space-y-4">
        {comments.length === 0 ? (
          <p className="text-muted-foreground text-center py-8">
            Пока нет комментариев. Будьте первым!
          </p>
        ) : (
          comments.map((comment) => (
            <div
              key={comment.id}
              className="cyber-card p-4 space-y-2"
            >
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center">
                  <User className="h-4 w-4 text-primary" />
                </div>
                <div>
                  <span className="font-mono text-sm font-bold">
                    {comment.author}
                  </span>
                  <span className="text-xs text-muted-foreground ml-2">
                    {new Date(comment.date).toLocaleDateString("ru-RU")}
                  </span>
                </div>
              </div>
              <p className="text-sm text-foreground/90 pl-10">
                {comment.content}
              </p>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
