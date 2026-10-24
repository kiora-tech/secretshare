// Boîte de réception d'une demande : la clé privée X-Wing est dans le fragment du lien.
// Comme pour un secret, rien n'est consommé sans geste humain : la page lit seulement l'état
// de la boîte, et la réponse (rendue une seule fois, puis effacée) ne part qu'après un appui
// maintenu. Un antivirus de messagerie ou un préchargement du navigateur ne la grille pas.

import { idFromPath, keyFromFragment, fromB64url, b64url } from '../lib/codec.js';
import { inboxAuth, openResponse } from '../lib/crypto.js';
import { unpack } from '../lib/payload.js';
import { api } from '../lib/api.js';
import { track } from '../lib/analytics.js';
import { el, show, error, formatDate, renderDownloads, apiMessage, holdButton } from '../lib/ui.js';

const id = idFromPath();
const secretKey = keyFromFragment();
const panels = ['loading', 'pending', 'ready', 'open', 'gone'];
const display = (name) => panels.forEach((p) => show(el(`#inbox-${p}`), p === name));
const errorBox = el('#inbox-error');
const readyError = el('#inbox-ready-error');

let token = null;
let busy = false;

async function load() {
    if (!id || !secretKey) {
        display('gone');
        return;
    }
    token ??= b64url(await inboxAuth(id, secretKey));
    const { status, data } = await api.inboxStatus(id, token);
    if (status === 404) {
        display('gone');
        return;
    }
    if (status !== 200) {
        display('pending');
        error(errorBox, apiMessage(status));
        return;
    }
    error(errorBox, null);
    el('#inbox-expires').textContent = formatDate(data.expiresAt);
    display(data.state === 'answered' ? 'ready' : 'pending');
}

async function open() {
    busy = true;
    error(readyError, null);
    try {
        const { status, data } = await api.openInbox(id, token);
        if (status === 404) {
            display('gone');
            return;
        }
        if (status !== 200) {
            error(readyError, apiMessage(status));
            return;
        }
        if (data.state === 'pending') {
            display('pending');
            return;
        }
        const plain = await openResponse(id, secretKey, fromB64url(data.kem, 1120), fromB64url(data.ciphertext));
        const { text, files } = unpack(plain);
        el('#inbox-text').textContent = text;
        el('#inbox-copy-source').value = text;
        show(el('#inbox-copy-row'), text.length > 0);
        renderDownloads(el('#inbox-files'), files);
        display('open');
        requestAnimationFrame(() => el('#inbox-box').classList.add('is-open'));
        // La réponse est effacée : la clé privée n'a plus d'usage, on la retire de l'historique.
        history.replaceState(null, '', location.pathname);
        track('request_opened');
    } catch (e) {
        console.error(e);
        error(readyError, 'The answer could not be decrypted with this link.');
    } finally {
        busy = false;
    }
}

async function cancelRequest() {
    busy = true;
    try {
        const { status } = await api.burnRequest(id, token);
        if (status !== 204) {
            error(errorBox, apiMessage(status));
            return;
        }
        display('gone');
    } finally {
        busy = false;
    }
}

holdButton(el('#inbox-submit'), { onHold: open, hint: el('#inbox-hint'), isBusy: () => busy });
holdButton(el('#inbox-cancel'), { onHold: cancelRequest, hint: el('#inbox-cancel-hint'), isBusy: () => busy });
el('#inbox-refresh').addEventListener('click', load);

// Rouvrir le lien dans le même onglet ne change que le fragment : sans rechargement, la page
// resterait sur l'état précédent.
addEventListener('hashchange', () => location.reload());

load();
