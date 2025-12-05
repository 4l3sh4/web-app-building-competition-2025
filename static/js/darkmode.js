document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('themeToggle');
    const html = document.documentElement;

    // Load saved theme preference
    const savedTheme = localStorage.getItem('theme') || 'light';
    if (savedTheme === 'dark') {
        html.classList.add('dark-mode');
    }

    // If the toggle exists, update its icon and attach handler
    if (themeToggle) {
        themeToggle.textContent = html.classList.contains('dark-mode') ? '☀️' : '🌙';

        themeToggle.addEventListener('click', () => {
            html.classList.toggle('dark-mode');
            const isDark = html.classList.contains('dark-mode');
            themeToggle.textContent = isDark ? '☀️' : '🌙';
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
        });
    }
});