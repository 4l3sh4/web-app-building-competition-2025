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
        const setIcon = (isDark) => {
            // When dark mode is active show the light-mode icon (sun),
            // otherwise show the dark-mode icon (moon).
            themeToggle.innerHTML = isDark
                ? '<img src="/static/assets/light-mode.png" alt="Light mode" class="theme-icon">'
                : '<img src="/static/assets/dark-mode.png" alt="Dark mode" class="theme-icon">';
        };

        setIcon(html.classList.contains('dark-mode'));

        themeToggle.addEventListener('click', () => {
            html.classList.toggle('dark-mode');
            const isDark = html.classList.contains('dark-mode');
            setIcon(isDark);
            localStorage.setItem('theme', isDark ? 'dark' : 'light');
        });
    }
});