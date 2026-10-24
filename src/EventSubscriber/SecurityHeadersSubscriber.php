<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * La politique de sécurité du contenu est posée ici et non par nginx : l'importmap et
 * l'amorce du module sont des scripts en ligne, autorisés par un nonce tiré à chaque requête.
 * Aucune autre origine n'est permise : une page qui affiche une clé n'exécute que notre code.
 */
final class SecurityHeadersSubscriber implements EventSubscriberInterface
{
    public const string NONCE_ATTRIBUTE = '_csp_nonce';
    /** Pages et API qui portent un identifiant de secret : jamais en cache, jamais indexées. */
    private const string PRIVATE_PATHS = '#^/(s|m|r|i|api)/#';

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onRequest', 512],
            KernelEvents::RESPONSE => ['onResponse', -16],
        ];
    }

    public function onRequest(RequestEvent $event): void
    {
        if ($event->isMainRequest()) {
            $event->getRequest()->attributes->set(self::NONCE_ATTRIBUTE, rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '='));
        }
    }

    public function onResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $request = $event->getRequest();
        $response = $event->getResponse();

        if (preg_match(self::PRIVATE_PATHS, $request->getPathInfo())) {
            $response->headers->set('Cache-Control', 'no-store');
            $response->headers->set('X-Robots-Tag', 'noindex, nofollow');
        }

        if (!str_contains((string) $response->headers->get('Content-Type', 'text/html'), 'text/html')) {
            return;
        }
        $nonce = (string) $request->attributes->get(self::NONCE_ATTRIBUTE);
        $response->headers->set('Content-Security-Policy', implode('; ', array_filter([
            "default-src 'none'",
            // wasm-unsafe-eval : Argon2id tourne en WebAssembly (hash-wasm), sans eval JavaScript.
            "script-src 'self' 'nonce-{$nonce}' 'wasm-unsafe-eval'",
            "style-src 'self'",
            "img-src 'self' data: blob:",
            "font-src 'self'",
            "connect-src 'self'",
            "manifest-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            // En production seulement : en local, le site est servi en HTTP sur localhost.
            $request->isSecure() ? 'upgrade-insecure-requests' : null,
        ])));
    }
}
