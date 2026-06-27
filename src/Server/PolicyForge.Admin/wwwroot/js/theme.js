// Light/dark theme toggle. Initial theme applied inline in <head> (App.razor).
(function () {
    function current() { return document.documentElement.getAttribute('data-bs-theme') || 'light'; }
    function apply(theme) {
        document.documentElement.setAttribute('data-bs-theme', theme);
        try { localStorage.setItem('cpm-theme', theme); } catch (e) {}
    }
    function persisted() {
        try {
            var t = localStorage.getItem('cpm-theme');
            if (!t) { t = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; }
            return t;
        } catch (e) { return 'light'; }
    }
    function reapply() { document.documentElement.setAttribute('data-bs-theme', persisted()); }
    window.cpmTheme = {
        toggle: function () { var t = current() === 'dark' ? 'light' : 'dark'; apply(t); return t === 'dark'; },
        isDark: function () { return current() === 'dark'; },
        set: apply, get: current, reapply: reapply
    };
    function register() {
        if (window.Blazor && typeof window.Blazor.addEventListener === 'function') {
            window.Blazor.addEventListener('enhancedload', reapply);
        } else { setTimeout(register, 50); }
    }
    register();
})();
