// Créer une demande : la paire de clés X-Wing naît ici, la clé privée ne quitte pas le navigateur.

import { b64url } from '../lib/codec.js';
import { createRequest } from '../lib/crypto.js';
import { api } from '../lib/api.js';
import { track } from '../lib/analytics.js';
import { el, show, busy, error, apiMessage } from '../lib/ui.js';

const form = el('#request-form');
const submit = el('#request-submit');
const errorBox = el('#request-error');

form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error(errorBox, null);
    busy(submit, 'Generating keys…');
    try {
        const ttl = Number(form.querySelector('input[name="ttl"]:checked').value);
        const note = el('#request-note').value.trim();
        let request = await createRequest(note, ttl);
        let response = await api.createRequest(request.body);
        if (response.status === 409) {
            request = await createRequest(note, ttl);
            response = await api.createRequest(request.body);
        }
        if (response.status !== 201) {
            error(errorBox, apiMessage(response.status));
            return;
        }

        const inbox = `${location.origin}/i/${request.id}#${b64url(request.secretKey)}`;
        el('#request-link').value = `${location.origin}/r/${request.id}#${b64url(request.requestKey)}`;
        el('#inbox-link').value = inbox;
        el('#inbox-open').href = inbox;
        form.reset();
        show(form, false);
        show(el('#request-result'), true);
        el('#request-link').select();
        track('request_created');
    } catch (e) {
        error(errorBox, 'Key generation failed in your browser. Please update it and try again.');
        console.error(e);
    } finally {
        busy(submit);
    }
});
