// Ce qui est chiffré : le texte, les fichiers joints, et du remplissage jusqu'à un palier
// fixe, pour que la taille du chiffré ne trahisse ni la longueur d'un mot de passe ni celle
// d'un fichier.
//
//   0x01 ‖ longueur de l'en-tête (4 octets, gros-boutiste) ‖ en-tête JSON ‖ fichiers ‖ zéros
//   en-tête = { text, files: [{ name, type, size }] }

import { utf8, fromUtf8 } from './codec.js';

export const MAX_FILES_BYTES = 10 * 1024 * 1024;
const SMALL = 4096;
const BLOCK = 64 * 1024;

export async function pack(text, files = []) {
    const total = files.reduce((n, f) => n + f.size, 0);
    if (total > MAX_FILES_BYTES) {
        throw new Error('too_large');
    }
    const header = utf8.encode(JSON.stringify({
        text,
        files: files.map((f) => ({ name: f.name, type: f.type || 'application/octet-stream', size: f.size })),
    }));
    const used = 5 + header.length + total;
    const out = new Uint8Array(used <= SMALL ? SMALL : Math.ceil(used / BLOCK) * BLOCK);

    out[0] = 1;
    new DataView(out.buffer).setUint32(1, header.length);
    out.set(header, 5);
    let offset = 5 + header.length;
    for (const file of files) {
        out.set(new Uint8Array(await file.arrayBuffer()), offset);
        offset += file.size;
    }
    return out;
}

export function unpack(bytes) {
    if (bytes[0] !== 1) {
        throw new Error('unsupported');
    }
    const length = new DataView(bytes.buffer, bytes.byteOffset).getUint32(1);
    const header = JSON.parse(fromUtf8.decode(bytes.subarray(5, 5 + length)));
    let offset = 5 + length;
    const files = header.files.map((f) => {
        const data = bytes.slice(offset, offset + f.size);
        offset += f.size;
        return { name: f.name, type: f.type, size: f.size, data };
    });
    return { text: header.text, files };
}
