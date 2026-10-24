// Suivi d'un secret par son expéditeur, sans compte : le jeton est dans le fragment du lien.

import { idFromPath, keyFromFragment, b64url } from '../lib/codec.js';
import { api } from '../lib/api.js';
import { track } from '../lib/analytics.js';
import { el, show, error, formatDate, apiMessage, holdButton } from '../lib/ui.js';

const id = idFromPath();
const tokenBytes = keyFromFragment();
const token = tokenBytes ? b64url(tokenBytes) : null;
const panels = ['loading', 'found', 'missing'];
const display = (name) => panels.forEach((p) => show(el(`#manage-${p}`), p === name));

const STATES = {
    active: { title: 'Waiting to be read.', badge: null },
    consumed: { title: 'Read, then destroyed.', badge: 'Destroyed' },
    expired: { title: 'Expired unread.', badge: 'Expired' },
    burned: { title: 'Burned.', badge: 'Burned' },
};

async function load() {
    if (!id || !token) {
        display('missing');
        return;
    }
    const { status, data } = await api.secretStatus(id, token);
    if (status === 404) {
        display('missing');
        return;
    }
    if (status !== 200) {
        display('found');
        error(el('#manage-error'), apiMessage(status));
        return;
    }

    const state = STATES[data.state] ?? STATES.active;
    el('#manage-title').textContent = data.state === 'burned' && data.burnReason === 'attempts'
        ? 'Destroyed after too many wrong passphrases.'
        : (data.state === 'active' && data.views > 0 ? 'Read, still available.' : state.title);
    const badge = el('#manage-status');
    badge.textContent = state.badge ?? '';
    show(badge, Boolean(state.badge));
    el('#manage-views').textContent = `${data.views} of ${data.maxViews}`;
    el('#manage-read').textContent = data.viewedAt.length ? data.viewedAt.map(formatDate).join(', ') : 'Not yet';
    el('#manage-created').textContent = formatDate(data.createdAt);
    el('#manage-expires').textContent = formatDate(data.expiresAt);
    show(el('#manage-actions'), data.state === 'active');
    display('found');
}

// Un appui maintenu plutôt qu'une boîte de confirmation : rien ne bloque la page, et un
// antivirus qui clique sur les boutons ne détruit rien.
let burning = false;
holdButton(el('#manage-burn'), {
    hint: el('#manage-burn-hint'),
    isBusy: () => burning,
    onHold: async () => {
        burning = true;
        try {
            const { status } = await api.burnSecret(id, token);
            if (status !== 204) {
                error(el('#manage-error'), apiMessage(status));
                return;
            }
            track('secret_burned');
            load();
        } finally {
            burning = false;
        }
    },
});

el('#manage-refresh').addEventListener('click', load);

// Rouvrir le lien dans le même onglet ne change que le fragment : sans rechargement, la page
// resterait sur l'état précédent.
addEventListener('hashchange', () => location.reload());

load();
