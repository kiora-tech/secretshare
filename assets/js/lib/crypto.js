// Le chiffrement de secretshare, tel que décrit sur /security. Tout se passe ici, dans le
// navigateur : le serveur ne reçoit que du chiffré et des empreintes SHA-256.
//
// Lien de secret   /s/<id>#<K>      K : 256 bits aléatoires, jamais envoyés au serveur
//   IKM          = K               (ou K ‖ Argon2id(phrase de passe) si une phrase est posée)
//   clé AES      = HKDF-SHA256(IKM, sel = "secretshare/v1/secret/<id>", info = "enc")
//   clé d'accès  = HKDF-SHA256(IKM, même sel, info = "auth") ; le serveur n'en garde que le SHA-256
//   preuve de lien = HKDF-SHA256(K, même sel, info = "link"), avec une phrase de passe seulement :
//                  le serveur la vérifie (SHA-256) avant de compter un essai, si bien que qui ne
//                  connaît que l'identifiant ne peut pas user les dix essais
//   chiffré      = 0x01 ‖ IV (96 bits) ‖ AES-256-GCM(données remplies, AAD = sel)
//
// Demande de secret   /r/<id>#<R>  (à envoyer)   /i/<id>#<sk>  (à garder)
//   X-Wing (ML-KEM-768 + X25519) : clé publique au serveur, clé privée sk (32 octets) dans le
//   fragment du lien de réception. La note du demandeur est chiffrée avec une clé tirée de R,
//   et son AAD contient le SHA-256 de la clé publique : un serveur qui substituerait sa propre
//   clé publique rendrait la note indéchiffrable, et le correspondant refuserait de répondre.
//   Répondre exige la preuve HKDF(R, "respond") : l'identifiant seul ne permet pas de répondre.

import { utf8, concat, randomBytes, b64url, fromB64url } from './codec.js';

const VERSION = 1;
const IV_LENGTH = 12;

export const KDF = Object.freeze({ alg: 'argon2id', m: 65536, t: 3, p: 1 });

const label = (kind, id) => utf8.encode(`secretshare/v${VERSION}/${kind}/${id}`);

export async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function hkdf(ikm, salt, info, length = 32) {
    const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt, info: utf8.encode(info) },
        key,
        length * 8,
    );
    return new Uint8Array(bits);
}

async function aesKey(raw, usage) {
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, [usage]);
}

export async function seal(keyBytes, plaintext, aad) {
    const iv = randomBytes(IV_LENGTH);
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        await aesKey(keyBytes, 'encrypt'),
        plaintext,
    );
    return concat(Uint8Array.of(VERSION), iv, new Uint8Array(ciphertext));
}

/** Lève une erreur si la clé, l'AAD ou le chiffré ne correspondent pas (étiquette GCM). */
export async function unseal(keyBytes, sealed, aad) {
    if (sealed.length < 1 + IV_LENGTH + 16 || sealed[0] !== VERSION) {
        throw new Error('unsupported');
    }
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: sealed.subarray(1, 1 + IV_LENGTH), additionalData: aad, tagLength: 128 },
        await aesKey(keyBytes, 'decrypt'),
        sealed.subarray(1 + IV_LENGTH),
    );
    return new Uint8Array(plaintext);
}

/** Argon2id : 64 Mio, 3 passes, parallélisme 1. Chargé seulement si besoin. */
export async function argon2id(passphrase, salt) {
    const { argon2id: run } = await import('hash-wasm');
    return run({
        password: utf8.encode(passphrase.normalize('NFC')),
        salt,
        parallelism: KDF.p,
        iterations: KDF.t,
        memorySize: KDF.m,
        hashLength: 32,
        outputType: 'binary',
    });
}

// ─── Lien de secret ──────────────────────────────────────────────────────────

export async function secretKeys(id, linkKey, passphraseKey = null) {
    const ikm = passphraseKey ? concat(linkKey, passphraseKey) : linkKey;
    const salt = label('secret', id);
    return {
        encKey: await hkdf(ikm, salt, 'enc'),
        authKey: await hkdf(ikm, salt, 'auth'),
        // Tirée de K seul : elle prouve la détention du lien, phrase de passe mise à part.
        linkProof: await hkdf(linkKey, salt, 'link'),
    };
}

/**
 * Chiffre des données déjà empaquetées (payload.js) et rend le corps de POST /api/secrets,
 * plus les deux clés qui ne quittent jamais le navigateur : celle du lien et celle du suivi.
 */
export async function createSecret(packed, { passphrase = '', maxViews, ttl }) {
    const id = b64url(randomBytes(16));
    const linkKey = randomBytes(32);
    const manageToken = randomBytes(32);

    let kdf = null;
    let passphraseKey = null;
    if (passphrase) {
        const salt = randomBytes(16);
        passphraseKey = await argon2id(passphrase, salt);
        kdf = { ...KDF, salt: b64url(salt) };
    }

    const { encKey, authKey, linkProof } = await secretKeys(id, linkKey, passphraseKey);
    const ciphertext = await seal(encKey, packed, label('secret', id));

    return {
        id,
        linkKey,
        manageToken,
        body: {
            id,
            ciphertext: b64url(ciphertext),
            authHash: b64url(await sha256(authKey)),
            manageHash: b64url(await sha256(manageToken)),
            linkHash: kdf ? b64url(await sha256(linkProof)) : null,
            kdf,
            maxViews,
            ttl,
        },
    };
}

export async function revealKeys(id, linkKey, kdf, passphrase) {
    const passphraseKey = kdf ? await argon2id(passphrase, fromB64url(kdf.salt, 16)) : null;
    return secretKeys(id, linkKey, passphraseKey);
}

export async function openSecret(id, encKey, ciphertext) {
    return unseal(encKey, ciphertext, label('secret', id));
}

// ─── Demande de secret (post-quantique) ──────────────────────────────────────

async function xwing() {
    const { ml_kem768_x25519 } = await import('@noble/post-quantum/hybrid.js');
    return ml_kem768_x25519;
}

async function noteAad(id, publicKey) {
    return concat(label('request', id), await sha256(publicKey));
}

export async function inboxAuth(id, secretKey) {
    return hkdf(secretKey, label('request', id), 'inbox');
}

/** La preuve de réponse : seul qui détient R (le lien de demande) peut répondre. */
export async function respondAuth(id, requestKey) {
    return hkdf(requestKey, label('request', id), 'respond');
}

export async function createRequest(noteText, ttl) {
    const kem = await xwing();
    const id = b64url(randomBytes(16));
    const { publicKey, secretKey } = kem.keygen();
    const requestKey = randomBytes(32);

    const noteKey = await hkdf(requestKey, label('request', id), 'note');
    const note = await seal(noteKey, pad(utf8.encode(noteText), 512), await noteAad(id, publicKey));

    return {
        id,
        requestKey,
        secretKey,
        body: {
            id,
            publicKey: b64url(publicKey),
            note: b64url(note),
            inboxHash: b64url(await sha256(await inboxAuth(id, secretKey))),
            respondHash: b64url(await sha256(await respondAuth(id, requestKey))),
            ttl,
        },
    };
}

/** Lève une erreur si la note ne s'ouvre pas : lien abîmé, ou clé publique substituée. */
export async function openRequestNote(id, requestKey, publicKey, note) {
    const noteKey = await hkdf(requestKey, label('request', id), 'note');
    return new TextDecoder().decode(unpad(await unseal(noteKey, note, await noteAad(id, publicKey))));
}

export async function sealResponse(id, publicKey, packed) {
    const kem = await xwing();
    const { cipherText, sharedSecret } = kem.encapsulate(publicKey);
    const key = await hkdf(sharedSecret, label('response', id), 'enc');
    return { kem: cipherText, ciphertext: await seal(key, packed, label('response', id)) };
}

export async function openResponse(id, secretKey, kemCiphertext, ciphertext) {
    const kem = await xwing();
    const sharedSecret = kem.decapsulate(kemCiphertext, secretKey);
    const key = await hkdf(sharedSecret, label('response', id), 'enc');
    return unseal(key, ciphertext, label('response', id));
}

// Note : longueur sur 2 octets, puis zéros jusqu'au palier, pour ne pas trahir sa taille.
function pad(bytes, block) {
    const out = new Uint8Array(Math.ceil((bytes.length + 2) / block) * block);
    out[0] = bytes.length >> 8;
    out[1] = bytes.length & 0xff;
    out.set(bytes, 2);
    return out;
}

function unpad(bytes) {
    return bytes.subarray(2, 2 + ((bytes[0] << 8) | bytes[1]));
}
