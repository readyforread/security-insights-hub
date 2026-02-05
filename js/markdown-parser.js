// Simple Markdown parser
const MarkdownParser = {
    // Parse front matter (metadata between ---)
    parseFrontMatter(content) {
        const match = content.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
        if (!match) {
            return { meta: {}, body: content };
        }
        
        const meta = {};
        const metaLines = match[1].split('\n');
        
        metaLines.forEach(line => {
            const colonIndex = line.indexOf(':');
            if (colonIndex === -1) return;
            
            const key = line.slice(0, colonIndex).trim();
            let value = line.slice(colonIndex + 1).trim();
            
            // Parse arrays [item1, item2]
            if (value.startsWith('[') && value.endsWith(']')) {
                value = value.slice(1, -1).split(',').map(s => s.trim());
            }
            // Parse numbers
            else if (!isNaN(value) && value !== '') {
                value = parseFloat(value);
            }
            
            meta[key] = value;
        });
        
        return { meta, body: match[2] };
    },
    
    // Convert Markdown to HTML
    toHTML(markdown) {
        let html = markdown;
        
        // Code blocks
        html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
            return `<pre><code class="language-${lang}">${this.escapeHtml(code.trim())}</code></pre>`;
        });
        
        // Inline code
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
        
        // Headers
        html = html.replace(/^#### (.+)$/gm, '<h4>$1</h4>');
        html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
        html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
        html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');
        
        // Bold and italic
        html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
        
        // Links
        html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
        
        // Unordered lists
        html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
        html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');
        
        // Ordered lists
        html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
        
        // Paragraphs
        html = html.split('\n\n').map(block => {
            block = block.trim();
            if (!block) return '';
            if (block.startsWith('<')) return block;
            return `<p>${block}</p>`;
        }).join('\n');
        
        // Clean up
        html = html.replace(/<p>\s*<\/p>/g, '');
        html = html.replace(/\n{3,}/g, '\n\n');
        
        return html;
    },
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};
