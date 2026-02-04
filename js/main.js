// Mobile menu toggle
document.addEventListener('DOMContentLoaded', function() {
    const menuBtn = document.getElementById('menuBtn');
    const nav = document.querySelector('.nav');
    
    if (menuBtn) {
        menuBtn.addEventListener('click', function() {
            // Create mobile nav if it doesn't exist
            let mobileNav = document.querySelector('.mobile-nav');
            
            if (!mobileNav) {
                mobileNav = document.createElement('nav');
                mobileNav.className = 'mobile-nav';
                mobileNav.innerHTML = `
                    <a href="index.html" class="nav-link">Главная</a>
                    <a href="about.html" class="nav-link">О блоге</a>
                `;
                document.querySelector('.header').appendChild(mobileNav);
            }
            
            mobileNav.classList.toggle('active');
            
            // Animate menu button
            const spans = menuBtn.querySelectorAll('span');
            spans.forEach(span => span.classList.toggle('active'));
        });
    }
});

// Smooth scroll for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth'
            });
        }
    });
});
