// Petits outils d'interface partagés par les pages.

export const el = (selector, root = document) => root.querySelector(selector);

export function show(element, visible = true) {
    element.hidden = !visible;
}

export function busy(button, label) {
    if (label) {
        button.dataset.label = button.innerHTML;
        button.disabled = true;
        button.innerHTML = `<span class="spinner" aria-hidden="true"></span> ${label}`;
    } else {
        button.disabled = false;
        button.innerHTML = button.dataset.label ?? button.innerHTML;
    }
}

export function error(element, message) {
    element.textContent = message ?? '';
    show(element, Boolean(message));
}

export function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function formatDate(iso) {
    return new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(iso));
}

export function views(n) {
    return n === 1 ? '1 time' : `${n} times`;
}

// Types que le navigateur affiche sans exécuter de script. Tout le reste part en
// application/octet-stream : un fichier HTML ou SVG déchiffré ne doit jamais s'ouvrir comme une
// page de secretshare.co, quel que soit le type écrit par l'expéditeur.
const INERT_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/pdf', 'text/plain']);
// Contrôles de direction (U+200E-200F, U+202A-202E, U+2066-2069) et caractères de contrôle :
// ils feraient passer « invoice\u202efdp.exe » pour un PDF.
const UNSAFE_NAME = /[\u0000-\u001f\u007f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
const objectUrls = [];
addEventListener('pagehide', () => objectUrls.splice(0).forEach((url) => URL.revokeObjectURL(url)));

export function safeFileName(name) {
    return String(name ?? '').replace(UNSAFE_NAME, '') || 'file';
}

/** Liste de fichiers déchiffrés, chacun téléchargeable par un lien blob: local. */
export function renderDownloads(list, files) {
    list.replaceChildren(...files.map((file) => {
        const type = INERT_TYPES.has(String(file.type).toLowerCase()) ? file.type : 'application/octet-stream';
        const url = URL.createObjectURL(new Blob([file.data], { type }));
        objectUrls.push(url);
        const name = safeFileName(file.name);
        const li = document.createElement('li');
        const link = document.createElement('a');
        link.href = url;
        link.download = name;
        link.textContent = `↓ ${name}`;
        const size = document.createElement('span');
        size.textContent = formatBytes(file.size);
        li.append(link, size);
        return li;
    }));
    show(list, files.length > 0);
}

const HOLD_MS = 900;

/**
 * Bouton à appui maintenu (.btn--hold, avec .btn__fill et .btn__label) : rien ne part sur un
 * simple clic. Les robots d'aperçu (Slack, Teams) n'exécutent rien, et les antivirus de
 * messagerie qui cliquent sur les boutons ne maintiennent pas.
 */
export function holdButton(button, { onHold, hint = null, isBusy = () => false }) {
    let timer = null;
    const start = () => {
        if (isBusy() || timer) {
            return;
        }
        button.classList.add('is-holding');
        timer = setTimeout(() => {
            timer = null;
            button.classList.remove('is-holding');
            onHold();
        }, HOLD_MS);
    };
    const cancel = () => {
        if (timer) {
            clearTimeout(timer);
            timer = null;
            button.classList.remove('is-holding');
        }
    };

    // Le bouton capture le pointeur : un doigt qui glisse un peu, ou un rendu qui bouge sous la
    // souris, n'interrompt pas l'appui ; seuls le relâchement et l'annulation l'arrêtent.
    button.addEventListener('pointerdown', (event) => {
        event.preventDefault();
        button.setPointerCapture(event.pointerId);
        start();
    });
    ['pointerup', 'pointercancel', 'lostpointercapture'].forEach((type) => button.addEventListener(type, cancel));
    // Un appui long ouvrirait le menu contextuel sur mobile.
    button.addEventListener('contextmenu', (event) => event.preventDefault());
    // Au clavier : maintenir Entrée ou Espace.
    button.addEventListener('keydown', (event) => {
        if ((event.key === 'Enter' || event.key === ' ') && !event.repeat) {
            event.preventDefault();
            start();
        }
    });
    button.addEventListener('keyup', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            cancel();
        }
    });
    // Un clic seul ne fait rien : il rappelle le geste.
    button.addEventListener('click', () => {
        if (hint && !isBusy() && !timer) {
            hint.classList.add('is-nudged');
            setTimeout(() => hint.classList.remove('is-nudged'), 600);
        }
    });
}

/** Message d'erreur lisible pour une réponse de l'API. */
export function apiMessage(status) {
    if (status === 429) return 'Too many attempts from your network. Wait a minute and try again.';
    if (status === 413) return 'That is too large. The limit is 10 MB of files.';
    if (status === 507) return 'Our storage is full right now. Please try again later.';
    if (status >= 500 || status === 0) return 'Our server had a problem. Nothing was sent. Please try again.';
    return 'Something went wrong. Please try again.';
}

/**
 * Champ de fichiers avec glisser-déposer. Rend un objet qui donne la liste courante.
 * onChange reçoit la taille totale, pour signaler un dépassement.
 */
export function filePicker({ input, dropzone, list, onChange }) {
    let files = [];

    function render() {
        list.replaceChildren(...files.map((file, index) => {
            const li = document.createElement('li');
            const name = document.createElement('span');
            name.textContent = `${file.name} · ${formatBytes(file.size)}`;
            const remove = document.createElement('button');
            remove.type = 'button';
            remove.textContent = 'Remove';
            remove.addEventListener('click', () => {
                files.splice(index, 1);
                render();
            });
            li.append(name, remove);
            return li;
        }));
        show(list, files.length > 0);
        onChange?.(files.reduce((n, f) => n + f.size, 0));
    }

    function add(newFiles) {
        files = files.concat([...newFiles]);
        render();
    }

    input.addEventListener('change', () => {
        add(input.files);
        input.value = '';
    });
    ['dragenter', 'dragover'].forEach((type) => dropzone.addEventListener(type, (event) => {
        event.preventDefault();
        dropzone.classList.add('is-over');
    }));
    ['dragleave', 'drop'].forEach((type) => dropzone.addEventListener(type, () => dropzone.classList.remove('is-over')));
    dropzone.addEventListener('drop', (event) => {
        event.preventDefault();
        add(event.dataTransfer.files);
    });

    return {
        get files() { return files; },
        get total() { return files.reduce((n, f) => n + f.size, 0); },
        clear() { files = []; render(); },
    };
}
