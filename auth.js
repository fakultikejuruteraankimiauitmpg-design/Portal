// auth.js — cookie-based session for FKK portal (no localStorage)
(function (global) {
    const COOKIE_NAME = 'fms_session';
    const TTL_SEC     = 8 * 60 * 60; // 8 hours

    // Auto-scope cookie path to the GitHub Pages repo folder.
    // /repo-name/login.html  ->  /repo-name/
    // /login.html            ->  /
    function cookiePath() {
        const p = location.pathname;
        const idx = p.lastIndexOf('/');
        return idx <= 0 ? '/' : p.slice(0, idx + 1);
    }

    function setCookie(name, value, seconds) {
        const parts = [
            name + '=' + encodeURIComponent(value),
            'path=' + cookiePath(),
            'max-age=' + seconds,
            'SameSite=Lax'
        ];
        if (location.protocol === 'https:') parts.push('Secure');
        document.cookie = parts.join('; ');
    }

    function getCookie(name) {
        const needle = name + '=';
        for (const raw of document.cookie.split(';')) {
            const c = raw.trim();
            if (c.startsWith(needle)) {
                try { return JSON.parse(decodeURIComponent(c.slice(needle.length))); }
                catch (e) { return null; }
            }
        }
        return null;
    }

    function deleteCookie(name) {
        document.cookie =
            name + '=; path=' + cookiePath() + '; max-age=0; SameSite=Lax';
    }

    function saveSession(user, role) {
        const payload = {
            user: { ...user, role },
            role,
            loginAt:   Date.now(),
            expiresAt: Date.now() + TTL_SEC * 1000
        };
        setCookie(COOKIE_NAME, JSON.stringify(payload), TTL_SEC);
    }

    function loadSession() {
        const s = getCookie(COOKIE_NAME);
        if (!s) return null;
        if (!s.expiresAt || Date.now() > s.expiresAt) {
            deleteCookie(COOKIE_NAME);
            return null;
        }
        return s;
    }

    function clearSession() { deleteCookie(COOKIE_NAME); }

    function requireAuth(allowedRoles) {
        const s = loadSession();
        if (!s) { location.replace('login.html'); return null; }
        if (allowedRoles && !allowedRoles.includes(s.role)) {
            location.replace('login.html');
            return null;
        }
        return s;
    }

    function touch() {
        const s = loadSession();
        if (!s) return;
        saveSession(s.user, s.role);
    }

    global.FMSAuth = { saveSession, loadSession, clearSession, requireAuth, touch };
})(window);
