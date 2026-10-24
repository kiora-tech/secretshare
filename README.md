# secretshare.co

Partage de secrets par lien qui s'autodétruit, chiffré dans le navigateur (AES-256-GCM, clé dans
le fragment), demande de secret post-quantique (X-Wing). Gratuit, sans compte.

La spécification publique du chiffrement est la page `/security`
(`templates/pages/security.html.twig`), le code dans `assets/js/lib/crypto.js`.

```bash
make up      # http://localhost:18108
make test    # PHPUnit
make e2e     # parcours complets dans Chromium
make qa      # PHPStan + style
```
