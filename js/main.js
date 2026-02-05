// Main app
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
        month: 'short', 
        year: 'numeric' 
    });
}

function renderPostCard(post) {
    let metaItems = [`<span>${formatDate(post.date)}</span>`];
    
    if (post.cvss) {
        metaItems.push(`<span class="cvss-badge ${getCvssClass(post.cvss)}">CVSS ${post.cvss}</span>`);
    }
    
    if (post.cve) {
        metaItems.push(`<span>${post.cve}</span>`);
    }
    
    const tagsHtml = post.tags.length > 0 
        ? `<div class="post-tags">${post.tags.map(t => `<span class="tag">${t}</span>`).join('')}</div>`
        : '';
    
    return `
        <article class="post-card">
            <h2><a href="post.html?id=${post.slug}">${post.title}</a></h2>
            <div class="post-meta">${metaItems.join('')}</div>
            ${post.excerpt ? `<p class="post-excerpt">${post.excerpt}</p>` : ''}
            ${tagsHtml}
        </article>
    `;
}

async function renderPosts() {
    const container = document.getElementById('postsList');
    if (!container) return;
    
    try {
        const posts = await PostsLoader.loadAll();
        
        if (posts.length === 0) {
            container.innerHTML = '<p class="loading">Нет постов. Добавьте .md файлы в папку posts/</p>';
            return;
        }
        
        container.innerHTML = posts.map(renderPostCard).join('');
    } catch (e) {
        container.innerHTML = '<p class="loading">Ошибка загрузки</p>';
        console.error(e);
    }
}

// Init on page load
document.addEventListener('DOMContentLoaded', renderPosts);
