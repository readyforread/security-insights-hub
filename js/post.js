// Get post ID from URL
function getPostId() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('id');
}

// Render post content
function renderPost() {
    const postId = getPostId();
    const post = postsData.find(p => p.id === postId);
    
    if (!post) {
        document.getElementById('postContent').innerHTML = `
            <div class="container">
                <p>Статья не найдена</p>
                <a href="index.html" class="back-link">← Вернуться на главную</a>
            </div>
        `;
        return;
    }
    
    // Update page title
    document.title = post.title + ' - SecureBlog';
    
    const cvssClass = getCvssClass(post.cvss);
    
    document.getElementById('postContent').innerHTML = `
        <div class="container">
            <div class="post-header">
                <a href="index.html" class="back-link">← Назад к статьям</a>
                <h1 class="post-title">${post.title}</h1>
                <div class="post-meta">
                    <span class="post-date">${post.date}</span>
                    <span class="post-author">Автор: ${post.author}</span>
                </div>
                <div class="post-tags">
                    ${post.tags.map(tag => `<span class="tag">${tag}</span>`).join('')}
                </div>
            </div>
            <div class="post-image">
                <img src="${post.image}" alt="${post.title}">
                <span class="cvss-badge ${cvssClass}">CVSS: ${post.cvss}</span>
            </div>
            ${post.cve ? `<p class="post-cve" style="margin-bottom: 1rem; color: var(--accent); font-family: monospace;">${post.cve}</p>` : ''}
            <div class="post-body">
                ${post.content}
            </div>
        </div>
    `;
}

// Render comments
function renderComments() {
    const postId = getPostId();
    const comments = getComments().filter(c => c.postId === postId);
    const container = document.getElementById('commentsList');
    
    if (comments.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary);">Пока нет комментариев. Будьте первым!</p>';
        return;
    }
    
    container.innerHTML = comments.map(comment => `
        <div class="comment">
            <div class="comment-header">
                <span class="comment-author">${comment.author}</span>
                <span class="comment-date">${comment.date}</span>
            </div>
            <p class="comment-content">${comment.content}</p>
        </div>
    `).join('');
}

// Handle comment form submission
document.getElementById('commentForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const author = document.getElementById('authorInput').value.trim();
    const content = document.getElementById('contentInput').value.trim();
    
    if (!author || !content) return;
    
    const comments = getComments();
    const newComment = {
        id: Date.now().toString(),
        postId: getPostId(),
        author: author,
        content: content,
        date: new Date().toLocaleDateString('ru-RU', { 
            day: 'numeric', 
            month: 'long', 
            year: 'numeric' 
        })
    };
    
    comments.push(newComment);
    saveComments(comments);
    
    // Clear form
    document.getElementById('authorInput').value = '';
    document.getElementById('contentInput').value = '';
    
    // Re-render comments
    renderComments();
});

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    renderPost();
    renderComments();
});
