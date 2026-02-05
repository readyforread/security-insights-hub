// Posts loader - loads markdown files from posts/ folder
const PostsLoader = {
    // List of post files (update this when adding new posts)
    postFiles: [
        'first-post.md'
    ],
    
    posts: [],
    
    async loadAll() {
        this.posts = [];
        
        for (const file of this.postFiles) {
            try {
                const response = await fetch(`posts/${file}`);
                if (!response.ok) continue;
                
                const content = await response.text();
                const { meta, body } = MarkdownParser.parseFrontMatter(content);
                
                // Extract excerpt from first paragraph
                const excerptMatch = body.match(/^([^#\n].*?)(\n\n|$)/);
                const excerpt = excerptMatch ? excerptMatch[1].trim() : '';
                
                this.posts.push({
                    id: file.replace('.md', ''),
                    slug: file.replace('.md', ''),
                    title: meta.title || 'Без названия',
                    date: meta.date || new Date().toISOString().split('T')[0],
                    author: meta.author || 'Автор',
                    cvss: meta.cvss || null,
                    cve: meta.cve || null,
                    tags: meta.tags || [],
                    image: meta.image || null,
                    excerpt: excerpt,
                    content: body
                });
            } catch (e) {
                console.error(`Failed to load ${file}:`, e);
            }
        }
        
        // Sort by date descending
        this.posts.sort((a, b) => new Date(b.date) - new Date(a.date));
        
        return this.posts;
    },
    
    getPost(slug) {
        return this.posts.find(p => p.slug === slug || p.id === slug);
    }
};
