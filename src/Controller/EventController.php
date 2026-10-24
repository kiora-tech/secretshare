<?php

declare(strict_types=1);

namespace App\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\DependencyInjection\Attribute\Target;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Les statistiques passent par ici plutôt que par le script de Plausible : aucune page qui
 * affiche une clé ne charge de code venu d'ailleurs, et ce qui part n'est qu'un gabarit de
 * chemin (/s, jamais /s/<id>), sans fragment ni identifiant.
 *
 * Le relais tient un worker php-fpm le temps de l'appel : il est donc limité par adresse,
 * réservé à nos propres pages, et coupé au bout d'une seconde quoi que fasse Plausible.
 */
final class EventController
{
    use ApiResponses;

    private const array EVENTS = [
        'pageview', 'secret_created', 'secret_revealed', 'secret_burned',
        'request_created', 'request_answered', 'request_opened',
    ];
    private const array PATHS = ['/', '/request', '/s', '/m', '/r', '/i', '/security', '/privacy', '/terms', '/404'];
    private const array QUERY = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'];

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly LoggerInterface $logger,
        #[Target('event.limiter')] private readonly RateLimiterFactoryInterface $eventLimiter,
        #[Autowire('%kernel.secret%')] private readonly string $kernelSecret,
        #[Autowire(env: 'PLAUSIBLE_URL')] private readonly string $plausibleUrl,
        #[Autowire(env: 'PLAUSIBLE_DOMAIN')] private readonly string $plausibleDomain,
    ) {
    }

    #[Route('/api/event', methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        if ($limited = $this->limited($this->eventLimiter, $request)) {
            return $limited;
        }
        $body = $this->json($request) ?? [];
        $name = $body['n'] ?? null;
        $path = $body['p'] ?? null;
        if (!\in_array($name, self::EVENTS, true) || !\in_array($path, self::PATHS, true)) {
            return new Response(status: 400);
        }
        if ('' === $this->plausibleDomain) {
            return new Response(status: 202);
        }

        $query = array_intersect_key(\is_array($body['q'] ?? null) ? $body['q'] : [], array_flip(self::QUERY));
        $query = array_filter($query, static fn ($v): bool => \is_string($v) && \strlen($v) <= 100);
        $referrer = \is_string($body['r'] ?? null) ? $this->origin($body['r']) : null;

        try {
            $this->httpClient->request('POST', rtrim($this->plausibleUrl, '/').'/api/event', [
                'timeout' => 1,
                'max_duration' => 1,
                'headers' => [
                    'User-Agent' => (string) $request->headers->get('User-Agent'),
                    'X-Forwarded-For' => (string) $request->getClientIp(),
                ],
                'json' => [
                    'name' => $name,
                    'domain' => $this->plausibleDomain,
                    'url' => 'https://'.$this->plausibleDomain.$path.($query ? '?'.http_build_query($query) : ''),
                    'referrer' => $referrer,
                ],
            ])->getStatusCode();
        } catch (\Throwable $e) {
            $this->logger->warning('Plausible injoignable : {message}', ['message' => $e->getMessage()]);
        }

        return new Response(status: 202);
    }

    /** Du référent, on ne garde que l'origine : un chemin peut contenir n'importe quoi. */
    private function origin(string $url): ?string
    {
        $parts = parse_url($url);
        if (!\is_array($parts) || !isset($parts['scheme'], $parts['host']) || !\in_array($parts['scheme'], ['http', 'https'], true)) {
            return null;
        }

        return $parts['scheme'].'://'.$parts['host'].'/';
    }
}
