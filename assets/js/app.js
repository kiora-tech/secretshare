// Chargé sur toutes les pages : la visite (gabarit de chemin seulement) et les boutons « Copy ».

import { track } from './lib/analytics.js';

track('pageview');

document.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-copy]');
    if (!button) {
        return;
    }
    const input = document.getElementById(button.dataset.copy);
    try {
        await navigator.clipboard.writeText(input.value);
    } catch {
        input.select();
        document.execCommand('copy');
    }
    const label = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => { button.textContent = label; }, 1600);
});
