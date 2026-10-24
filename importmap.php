<?php

/**
 * Returns the importmap for this application.
 *
 * - "path" is a path inside the asset mapper system. Use the
 *     "debug:asset-map" command to see the full list of paths.
 *
 * - "entrypoint" (JavaScript only) set to true for any module that will
 *     be used as an "entrypoint" (and passed to the importmap() Twig function).
 *
 * The "importmap:require" command can be used to add new entries to this file.
 *
 * @return array<string, array{    // Import name as key, description of the imported file as value
 *     path: string,               // Logical, relative or absolute path to the file
 *     type?: 'js'|'css'|'json',   // Type of the file, defaults to 'js'
 *     entrypoint?: bool,          // Whether the file is an entrypoint, for 'js' only
 * }|array{
 *     version: string,            // Version of the remote package
 *     package_specifier?: string, // Remote "package-name/path" specifier, defaults to the import name
 *     type?: 'js'|'css'|'json',
 *     entrypoint?: bool,
 * }>
 */
return [
    // Commun à toutes les pages : statistiques et boutons « Copy ».
    'app' => ['path' => './assets/js/app.js', 'entrypoint' => true],
    // Une entrée par page : le module post-quantique ne se charge que là où il sert.
    'pages/create' => ['path' => './assets/js/pages/create.js', 'entrypoint' => true],
    'pages/reveal' => ['path' => './assets/js/pages/reveal.js', 'entrypoint' => true],
    'pages/manage' => ['path' => './assets/js/pages/manage.js', 'entrypoint' => true],
    'pages/request-new' => ['path' => './assets/js/pages/request-new.js', 'entrypoint' => true],
    'pages/respond' => ['path' => './assets/js/pages/respond.js', 'entrypoint' => true],
    'pages/inbox' => ['path' => './assets/js/pages/inbox.js', 'entrypoint' => true],
    '@noble/post-quantum/hybrid.js' => ['version' => '0.7.1'],
    'hash-wasm' => ['version' => '4.12.0'],
    '@noble/curves/abstract/edwards.js' => ['version' => '2.4.0'],
    '@noble/curves/abstract/montgomery.js' => ['version' => '2.4.0'],
    '@noble/curves/abstract/weierstrass.js' => ['version' => '2.4.0'],
    '@noble/curves/ed25519.js' => ['version' => '2.4.0'],
    '@noble/curves/nist.js' => ['version' => '2.4.0'],
    '@noble/curves/utils.js' => ['version' => '2.4.0'],
    '@noble/hashes/hkdf.js' => ['version' => '2.4.0'],
    '@noble/hashes/sha2.js' => ['version' => '2.4.0'],
    '@noble/hashes/sha3.js' => ['version' => '2.4.0'],
    '@noble/hashes/utils.js' => ['version' => '2.4.0'],
    '@noble/curves/abstract/fft.js' => ['version' => '2.4.0'],
    '@noble/hashes/hmac.js' => ['version' => '2.4.0'],
];
