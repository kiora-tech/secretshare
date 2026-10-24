// Les appels à l'API. Toute réponse, erreur comprise, revient sous la forme { status, data } :
// c'est l'appelant qui décide selon le statut.

async function call(method, path, { body, token } = {}) {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) {
        headers['Content-Type'] = 'application/json';
    }
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
    });
    const text = await response.text();
    let data = null;
    try {
        data = text ? JSON.parse(text) : null;
    } catch {
        data = null;
    }
    return { status: response.status, data };
}

export const api = {
    createSecret: (body) => call('POST', '/api/secrets', { body }),
    secretMeta: (id) => call('GET', `/api/secrets/${id}`),
    revealSecret: (id, auth, link) => call('POST', `/api/secrets/${id}/reveal`, { body: link ? { auth, link } : { auth } }),
    secretStatus: (id, token) => call('GET', `/api/secrets/${id}/status`, { token }),
    burnSecret: (id, token) => call('DELETE', `/api/secrets/${id}`, { token }),

    createRequest: (body) => call('POST', '/api/requests', { body }),
    requestForResponder: (id) => call('GET', `/api/requests/${id}`),
    respond: (id, body, token) => call('POST', `/api/requests/${id}/respond`, { body, token }),
    inboxStatus: (id, token) => call('GET', `/api/requests/${id}/status`, { token }),
    openInbox: (id, token) => call('POST', `/api/requests/${id}/open`, { token }),
    burnRequest: (id, token) => call('DELETE', `/api/requests/${id}`, { token }),
};
