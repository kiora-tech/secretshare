// Encodages partagés avec le serveur : base64url sans remplissage (RFC 4648 §5).

export const utf8 = new TextEncoder();
export const fromUtf8 = new TextDecoder('utf-8', { fatal: true });

export function randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

export function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

export function b64url(bytes) {
    // Par tranches : String.fromCharCode(...bytes) déborde la pile au-delà de ~100 Ko.
    let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64url(text, expectedLength = null) {
    if (typeof text !== 'string' || !/^[A-Za-z0-9_-]+$/.test(text)) {
        throw new Error('malformed');
    }
    const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    if (expectedLength !== null && bytes.length !== expectedLength) {
        throw new Error('malformed');
    }
    return bytes;
}

/** L'identifiant est le dernier segment du chemin : /s/<id>, /m/<id>, /r/<id>, /i/<id>. */
export function idFromPath() {
    const match = location.pathname.match(/^\/[smri]\/([A-Za-z0-9_-]{22})$/);
    return match ? match[1] : null;
}

/** La clé vit dans le fragment, que le navigateur n'envoie jamais au serveur. */
export function keyFromFragment() {
    try {
        return fromB64url(location.hash.slice(1), 32);
    } catch {
        return null;
    }
}
