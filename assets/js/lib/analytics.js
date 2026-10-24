// Les statistiques passent par notre serveur (/api/event), qui relaie à Plausible : aucun
// script extérieur sur une page qui affiche une clé. Ne part qu'un gabarit de chemin (/s, jamais
// /s/<id>), et jamais le fragment.

const TEMPLATES = { s: '/s', m: '/m', r: '/r', i: '/i' };

function template() {
    const first = location.pathname.split('/')[1] ?? '';
    if (first in TEMPLATES) {
        return TEMPLATES[first];
    }
    return location.pathname.replace(/\/$/, '') || '/';
}

export function track(name) {
    const query = {};
    for (const [key, value] of new URLSearchParams(location.search)) {
        if (key.startsWith('utm_')) {
            query[key] = value;
        }
    }
    const body = JSON.stringify({ n: name, p: template(), r: document.referrer || null, q: query });
    try {
        fetch('/api/event', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body,
            keepalive: true,
            credentials: 'omit',
            referrerPolicy: 'no-referrer',
        }).catch(() => {});
    } catch {
        // Les statistiques ne doivent jamais gêner le service.
    }
}
