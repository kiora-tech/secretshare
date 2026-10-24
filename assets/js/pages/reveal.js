// Lire un secret : rien n'est demandé au serveur, hors l'état du lien, avant un geste humain.
// Le geste est un appui maintenu, pas un clic : les robots d'aperçu (Slack, Teams) n'exécutent
// rien, et les antivirus de messagerie qui cliquent sur les boutons ne maintiennent pas.

import { idFromPath, keyFromFragment, fromB64url, b64url } from '../lib/codec.js';
import { revealKeys, openSecret } from '../lib/crypto.js';
import { unpack } from '../lib/payload.js';
import { api } from '../lib/api.js';
import { track } from '../lib/analytics.js';
import { el, show, error, formatDate, views, renderDownloads, apiMessage, holdButton } from '../lib/ui.js';

const id = idFromPath();
const linkKey = keyFromFragment();
const panels = ['loading', 'ready', 'open', 'gone', 'broken'];
const display = (name) => panels.forEach((p) => show(el(`#reveal-${p}`), p === name));
const button = el('#reveal-submit');
const label = el('#reveal-submit .btn__label');
const errorBox = el('#reveal-error');

let kdf = null;
// Vrai seulement quand le serveur a dit si une phrase de passe est requise : avant cela, rien
// n'est dérivé ni envoyé, sinon un appui après une erreur (429, 5xx) userait un essai sans
// la phrase de passe.
let metaLoaded = false;
let busy = false;

async function init() {
    if (!id || !linkKey) {
        display('broken');
        return;
    }
    const { status, data } = await api.secretMeta(id);
    if (status === 404) {
        display('gone');
        return;
    }
    if (status !== 200) {
        display('ready');
        error(errorBox, apiMessage(status));
        return;
    }
    kdf = data.kdf;
    metaLoaded = true;
    el('#reveal-views').textContent = views(data.viewsLeft);
    el('#reveal-expires').textContent = formatDate(data.expiresAt);
    show(el('#reveal-pass-field'), Boolean(kdf));
    error(errorBox, null);
    display('ready');
}

async function reveal() {
    if (!metaLoaded) {
        busy = true;
        try {
            await init();
        } catch (e) {
            error(errorBox, apiMessage(0));
            console.error(e);
            return;
        } finally {
            busy = false;
        }
        // Une phrase de passe est requise : le champ vient d'apparaître, on attend qu'elle soit tapée.
        if (!metaLoaded || kdf) {
            return;
        }
    }
    const passphrase = el('#reveal-pass').value;
    error(errorBox, null);
    if (kdf && !passphrase) {
        error(errorBox, 'Type the passphrase the sender gave you.');
        el('#reveal-pass').focus();
        return;
    }

    busy = true;
    // Pas d'attribut disabled : Chrome perdrait le relâchement du bouton désactivé pendant
    // l'appui, et l'appui suivant (après une mauvaise phrase) ne partirait plus.
    button.setAttribute('aria-disabled', 'true');
    label.textContent = kdf ? 'Checking passphrase…' : 'Decrypting…';
    try {
        const { encKey, authKey, linkProof } = await revealKeys(id, linkKey, kdf, passphrase);
        const { status, data } = await api.revealSecret(id, b64url(authKey), kdf ? b64url(linkProof) : null);
        if (status === 403) {
            const left = data?.attemptsLeft ?? 0;
            error(errorBox, data?.error === 'wrong_key'
                ? `Wrong passphrase. ${left} attempt${left === 1 ? '' : 's'} left before the secret is destroyed.`
                : 'This link does not match the secret. Ask the sender to copy it again.');
            return;
        }
        if (status === 404) {
            display('gone');
            return;
        }
        if (status !== 200) {
            error(errorBox, apiMessage(status));
            return;
        }

        const { text, files } = unpack(await openSecret(id, encKey, fromB64url(data.ciphertext)));
        el('#reveal-text').textContent = text;
        el('#reveal-copy-source').value = text;
        show(el('#reveal-copy-row'), text.length > 0);
        renderDownloads(el('#reveal-files'), files);
        show(el('#reveal-status'), data.viewsLeft === 0);
        el('#reveal-after').textContent = data.viewsLeft === 0
            ? 'This secret has now been deleted from our servers. Copy it before you leave this page: it cannot be shown again.'
            : `It can be viewed ${views(data.viewsLeft)} more. Copy it now all the same.`;
        display('open');
        requestAnimationFrame(() => el('#reveal-box').classList.add('is-open'));
        // La clé n'a plus d'usage : on la retire de la barre d'adresse et de l'historique.
        history.replaceState(null, '', location.pathname);
        track('secret_revealed');
    } catch (e) {
        error(errorBox, 'Decryption failed. The link may be damaged: ask the sender to copy it again.');
        console.error(e);
    } finally {
        busy = false;
        button.removeAttribute('aria-disabled');
        label.textContent = 'Press and hold to reveal';
    }
}

holdButton(button, { onHold: reveal, hint: el('#reveal-hint'), isBusy: () => busy });
// Entrée dans le champ de la phrase ne révèle rien : il faut le geste.
el('#reveal-form').addEventListener('submit', (event) => event.preventDefault());

// Rouvrir le lien dans le même onglet ne change que le fragment : sans rechargement, la page
// resterait sur l'état précédent.
addEventListener('hashchange', () => location.reload());

init();
