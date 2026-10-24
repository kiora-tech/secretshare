// Page d'accueil : chiffre le secret dans le navigateur, envoie le chiffré, affiche les liens.

import { b64url } from '../lib/codec.js';
import { createSecret } from '../lib/crypto.js';
import { pack, MAX_FILES_BYTES } from '../lib/payload.js';
import { api } from '../lib/api.js';
import { track } from '../lib/analytics.js';
import { el, show, busy, error, formatBytes, formatDate, views, apiMessage, filePicker } from '../lib/ui.js';

const form = el('#create-form');
const result = el('#create-result');
const text = el('#secret-text');
const fileInput = el('#secret-files');
const viewsOutput = el('#views-output');
const passToggle = el('#passphrase-toggle');
const passField = el('#passphrase-field');
const passInput = el('#passphrase');
const submit = el('#create-submit');
const errorBox = el('#create-error');

let maxViews = 1;

const picker = filePicker({
    input: fileInput,
    dropzone: el('#dropzone'),
    list: el('#file-list'),
    onChange: (total) => error(errorBox, total > MAX_FILES_BYTES ? `Files add up to ${formatBytes(total)}. The limit is 10 MB.` : null),
});

form.querySelectorAll('[data-step]').forEach((button) => button.addEventListener('click', () => {
    maxViews = Math.min(10, Math.max(1, maxViews + Number(button.dataset.step)));
    viewsOutput.textContent = views(maxViews);
}));

passToggle.addEventListener('change', () => {
    show(passField, passToggle.checked);
    if (passToggle.checked) {
        passInput.focus();
    }
});

form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error(errorBox, null);

    const { files, total } = picker;
    if (!text.value.trim() && files.length === 0) {
        error(errorBox, 'Write a secret or attach a file first.');
        text.focus();
        return;
    }
    if (total > MAX_FILES_BYTES) {
        error(errorBox, `Files add up to ${formatBytes(total)}. The limit is 10 MB.`);
        return;
    }
    const passphrase = passToggle.checked ? passInput.value : '';
    if (passToggle.checked && passphrase.length < 4) {
        error(errorBox, 'Choose a passphrase of at least 4 characters, or turn the option off.');
        passInput.focus();
        return;
    }

    busy(submit, passphrase ? 'Hardening passphrase…' : 'Encrypting…');
    try {
        const ttl = Number(form.querySelector('input[name="ttl"]:checked').value);
        const packed = await pack(text.value, files);
        let secret = await createSecret(packed, { passphrase, maxViews, ttl });
        let response = await api.createSecret(secret.body);
        if (response.status === 409) {
            // Collision d'identifiant aléatoire de 128 bits : improbable, mais on recommence proprement.
            secret = await createSecret(packed, { passphrase, maxViews, ttl });
            response = await api.createSecret(secret.body);
        }
        if (response.status !== 201) {
            error(errorBox, apiMessage(response.status));
            return;
        }

        el('#share-link').value = `${location.origin}/s/${secret.id}#${b64url(secret.linkKey)}`;
        el('#manage-link').value = `${location.origin}/m/${secret.id}#${b64url(secret.manageToken)}`;
        el('#share-summary').textContent = `Works ${views(maxViews)}, expires ${formatDate(response.data.expiresAt)}.`;
        el('#share-message').value = [
            `I've sent you a secret through secretshare: ${el('#share-link').value}`,
            `Open it when you're ready to save it: it works ${views(maxViews)}, until ${formatDate(response.data.expiresAt)}, then it is destroyed.`,
            passphrase ? "You'll need the passphrase, which I'm sending you separately." : '',
            'To reveal it, press and hold the button for a second.',
        ].filter(Boolean).join('\n');
        show(el('#share-passphrase'), Boolean(passphrase));
        show(el('#share-scanner-tip'), !passphrase);

        // Le texte clair ne reste pas dans la page une fois scellé.
        form.reset();
        picker.clear();
        show(passField, false);
        show(form, false);
        show(result, true);
        result.scrollIntoView({ behavior: 'smooth', block: 'start' });
        el('#share-link').select();
        track('secret_created');
    } catch (e) {
        error(errorBox, 'Encryption failed in your browser. Please update it and try again.');
        console.error(e);
    } finally {
        busy(submit);
    }
});

el('#create-again').addEventListener('click', () => {
    maxViews = 1;
    viewsOutput.textContent = views(1);
    el('#share-link').value = '';
    el('#manage-link').value = '';
    el('#share-message').value = '';
    show(result, false);
    show(form, true);
    text.focus();
});
