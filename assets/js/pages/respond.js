// Répondre à une demande : vérifier la clé publique (par la note), chiffrer pour elle, envoyer.

import { idFromPath, keyFromFragment, fromB64url, b64url } from '../lib/codec.js';
import { openRequestNote, sealResponse, respondAuth } from '../lib/crypto.js';
import { pack, MAX_FILES_BYTES } from '../lib/payload.js';
import { api } from '../lib/api.js';
import { track } from '../lib/analytics.js';
import { el, show, busy, error, formatBytes, apiMessage, filePicker } from '../lib/ui.js';

const id = idFromPath();
const requestKey = keyFromFragment();
const panels = ['loading', 'form', 'sent', 'gone', 'broken'];
const display = (name) => panels.forEach((p) => show(el(`#respond-${p}`), p === name));
const errorBox = el('#respond-error');

let publicKey = null;

const picker = filePicker({
    input: el('#respond-files'),
    dropzone: el('#respond-dropzone'),
    list: el('#respond-file-list'),
    onChange: (total) => error(errorBox, total > MAX_FILES_BYTES ? `Files add up to ${formatBytes(total)}. The limit is 10 MB.` : null),
});

async function init() {
    if (!id || !requestKey) {
        display('broken');
        return;
    }
    const { status, data } = await api.requestForResponder(id);
    if (status === 404) {
        display('gone');
        return;
    }
    if (status !== 200) {
        display('form');
        error(errorBox, apiMessage(status));
        return;
    }
    try {
        publicKey = fromB64url(data.publicKey, 1216);
        // Si la note ne s'ouvre pas, la clé publique n'est pas celle du demandeur : on refuse.
        const note = await openRequestNote(id, requestKey, publicKey, fromB64url(data.note));
        const quote = el('#respond-note');
        quote.textContent = note;
        show(quote, note.length > 0);
        display('form');
    } catch (e) {
        console.error(e);
        display('broken');
    }
}

el('#respond-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    error(errorBox, null);
    const text = el('#respond-text').value;
    const { files, total } = picker;
    if (!text.trim() && files.length === 0) {
        error(errorBox, 'Type the secret or attach a file first.');
        return;
    }
    if (total > MAX_FILES_BYTES) {
        error(errorBox, `Files add up to ${formatBytes(total)}. The limit is 10 MB.`);
        return;
    }

    const submit = el('#respond-submit');
    busy(submit, 'Encrypting…');
    try {
        const sealed = await sealResponse(id, publicKey, await pack(text, files));
        const { status } = await api.respond(
            id,
            { kem: b64url(sealed.kem), ciphertext: b64url(sealed.ciphertext) },
            b64url(await respondAuth(id, requestKey)),
        );
        if (status === 404) {
            display('gone');
            return;
        }
        if (status !== 201) {
            error(errorBox, apiMessage(status));
            return;
        }
        el('#respond-text').value = '';
        picker.clear();
        display('sent');
        history.replaceState(null, '', location.pathname);
        track('request_answered');
    } catch (e) {
        error(errorBox, 'Encryption failed in your browser. Please update it and try again.');
        console.error(e);
    } finally {
        busy(submit);
    }
});

// Rouvrir le lien dans le même onglet ne change que le fragment : sans rechargement, la page
// resterait sur l'état précédent.
addEventListener('hashchange', () => location.reload());

init();
