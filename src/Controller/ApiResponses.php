<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

/**
 * Ce que les API ont en commun : lire le JSON, refuser poliment, compter les appels.
 */
trait ApiResponses
{
    /** Un identifiant de lien : 128 bits en base64url, sans rien après (pas même un saut de ligne). */
    private static function validId(mixed $id): ?string
    {
        return \is_string($id) && preg_match('/^[A-Za-z0-9_-]{22}\z/', $id) ? $id : null;
    }

    /** @return array<string, mixed>|null */
    private function json(Request $request): ?array
    {
        if (!self::isJson($request)) {
            return null;
        }
        try {
            $body = json_decode($request->getContent(), true, 8, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return \is_array($body) ? $body : null;
    }

    /** @param array<string, mixed> $extra */
    private function error(string $code, int $status, array $extra = []): JsonResponse
    {
        return new JsonResponse(['error' => $code] + $extra, $status);
    }

    /**
     * Compte l'appel contre la limite de l'adresse, après avoir écarté ce qu'un autre site peut
     * faire envoyer au navigateur du visiteur : sans cela, n'importe quelle page userait le quota
     * de ses visiteurs, et de tous ceux qui partagent leur adresse.
     *
     * Le compteur est rangé sous un HMAC de l'adresse (clé : APP_SECRET), jamais sous l'adresse
     * elle-même. Une adresse IPv6 compte pour son /64 : un abonné en détient au moins autant.
     */
    private function limited(RateLimiterFactoryInterface $factory, Request $request, int $tokens = 1): ?JsonResponse
    {
        // Fetch Metadata : « none » est une adresse tapée à la main, « same-origin » nos pages.
        $site = $request->headers->get('Sec-Fetch-Site');
        if (null !== $site && 'same-origin' !== $site && 'none' !== $site) {
            return $this->error('cross_site', 403);
        }
        // Sans prévol CORS, un autre site ne peut envoyer ni application/json ni Authorization :
        // l'exiger avant de compter couvre aussi les navigateurs qui n'envoient pas Sec-Fetch-Site.
        if ($request->isMethod('POST') && !$request->headers->has('Authorization') && !self::isJson($request)) {
            return $this->error('invalid_json', 400);
        }

        $limit = $factory->create($this->rateKey($request))->consume($tokens);
        if ($limit->isAccepted()) {
            return null;
        }
        $response = $this->error('rate_limited', 429);
        $response->headers->set('Retry-After', (string) max(1, $limit->getRetryAfter()->getTimestamp() - time()));

        return $response;
    }

    private function rateKey(Request $request): string
    {
        if (\strlen($this->kernelSecret) < 32) {
            throw new \LogicException('APP_SECRET must be at least 32 bytes: it keys the rate-limit counters.');
        }
        $ip = (string) $request->getClientIp();
        $ip = '' === $ip ? $ip : IpUtils::anonymize($ip, 0, 8);

        return hash_hmac('sha256', $ip, $this->kernelSecret);
    }

    /** Le jeton de suivi, de réception ou de réponse voyage dans l'en-tête, jamais dans l'URL. */
    private function bearer(Request $request): ?string
    {
        $header = (string) $request->headers->get('Authorization');

        return str_starts_with($header, 'Bearer ') ? substr($header, 7) : null;
    }

    private static function isJson(Request $request): bool
    {
        return str_starts_with((string) $request->headers->get('Content-Type'), 'application/json');
    }
}
