// Post page
function getPostSlug() {
    const params = new URLSearchParams(window.location.search);
    return params.get('id');
}

function getCvssClass(cvss) {
    if (cvss >= 9.0) return 'cvss-critical';
    if (cvss >= 7.0) return 'cvss-high';
    if (cvss >= 4.0) return 'cvss-medium';
    if (cvss > 0) return 'cvss-low';
    return '';
}

function formatDate(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleDateString('ru-RU', { 
        day: 'numeric', 
        month: 'long', 
        year: 'numeric' 
    });
}

async function renderPost() {
    const container = document.getElementById('postContent');
    const slug = getPostSlug();
    
    if (!slug) {
        container.innerHTML = '<div class="container"><p>Пост не найден</p><a href="index.html" class="back-link">← Назад</a></div>';
        return;
    }
    
    try {
        await PostsLoader.loadAll();
        const post = PostsLoader.getPost(slug);
        
        if (!post) {
            container.innerHTML = '<div class="container"><p>Пост не найден</p><a href="index.html" class="back-link">← Назад</a></div>';
            return;
        }
        
        document.title = `${post.title} - Security Blog`;
        
        let metaItems = [`<span>${formatDate(post.date)}</span>`];
        if (post.author) metaItems.push(`<span>${post.author}</span>`);
        if (post.cvss) metaItems.push(`<span class="cvss-badge ${getCvssClass(post.cvss)}">CVSS ${post.cvss}</span>`);
        if (post.cve) metaItems.push(`<span>${post.cve}</span>`);
        
        const tagsHtml = post.tags.length > 0 
            ? `<div class="post-tags">${post.tags.map(t => `<span class="tag">${t}</span>`).join('')}</div>`
            : '';
        
        const contentHtml = MarkdownParser.toHTML(post.content);
        
        container.innerHTML = `
            <div class="container">
                <div class="post-header">
                    <a href="index.html" class="back-link">← Назад к постам</a>
                    <h1>${post.title}</h1>
                    <div class="post-meta">${metaItems.join('')}</div>
                    ${tagsHtml}
                </div>
                <div class="post-body">
                    ${contentHtml}
                </div>
            </div>
        `;
    } catch (e) {
        container.innerHTML = '<div class="container"><p>Ошибка загрузки</p></div>';
        console.error(e);
    }
}

document.addEventListener('DOMContentLoaded', renderPost);
