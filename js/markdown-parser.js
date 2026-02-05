// Simple but safe Markdown parser
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

            // Parse arrays: [a, b]
            if (value.startsWith('[') && value.endsWith(']')) {
                value = value.slice(1, -1).split(',').map(v => v.trim());
            }
            // Parse numbers
            else if (!isNaN(value) && value !== '') {
                value = Number(value);
            }

            meta[key] = value;
        });

        return { meta, body: match[2] };
    },

    // Convert Markdown to HTML
    toHTML(markdown) {
        let html = markdown;

        /* =========================
           CODE BLOCKS (SAFE)
        ========================== */
        const codeBlocks = [];

        html = html.replace(/```(\w*)\s*([\s\S]*?)```/g, (_, lang, code) => {
            const index = codeBlocks.length;
            codeBlocks.push(
                `<pre><code class="language-${lang || 'text'}">${this.escapeHtml(code.trim())}</code></pre>`
            );
            return `@@CODEBLOCK_${index}@@`;
        });

        /* =========================
           INLINE CODE
        ========================== */
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

        /* =========================
           HEADERS
        ========================== */
        html = html.replace(/^#### (.+)$/gm, '<h4>$1</h4>');
        html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
        html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
        html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');

        /* =========================
           BOLD / ITALIC
        ========================== */
        html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');

        /* =========================
           LINKS
        ========================== */
        html = html.replace(
            /\[([^\]]+)\]\(([^)]+)\)/g,
            '<a href="$2" target="_blank" rel="noopener">$1</a>'
        );

        /* =========================
           LISTS
        ========================== */
        html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
        html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');

        html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');

        /* =========================
           PARAGRAPHS
        ========================== */
        html = html
            .split(/\n{2,}/)
            .map(block => {
                block = block.trim();
                if (!block) return '';
                if (block.startsWith('<')) return block;
                return `<p>${block}</p>`;
            })
            .join('\n');

        /* =========================
           RESTORE CODE BLOCKS
        ========================== */
        codeBlocks.forEach((block, i) => {
            html = html.replace(`@@CODEBLOCK_${i}@@`, block);
        });

        return html;
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};
