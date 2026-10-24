<?php

declare(strict_types=1);

namespace App\Command;

use App\Secret\RequestStore;
use App\Secret\SecretStore;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\PruneableInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Les lectures refusent déjà ce qui a expiré ; la purge efface les lignes elles-mêmes, et les
 * compteurs de débit expirés de cache_items (sous HMAC de l'adresse IP), que l'adaptateur
 * Doctrine ne supprime que si la même adresse revient.
 * Lancée toutes les cinq minutes par le service scheduler de la stack.
 */
#[AsCommand('app:purge', 'Efface les secrets, les demandes et les compteurs de débit expirés')]
final class PurgeCommand
{
    public function __construct(
        private readonly SecretStore $secrets,
        private readonly RequestStore $requests,
        #[Autowire(service: 'cache.rate_limiter')] private readonly CacheItemPoolInterface $rateLimiterPool,
    ) {
    }

    public function __invoke(SymfonyStyle $io): int
    {
        $secrets = $this->secrets->purgeExpired();
        $requests = $this->requests->purgeExpired();
        if ($this->rateLimiterPool instanceof PruneableInterface) {
            $this->rateLimiterPool->prune();
        }
        $io->writeln(\sprintf('%s · %d secret(s), %d demande(s) effacé(s)', date(\DATE_ATOM), $secrets, $requests));

        return Command::SUCCESS;
    }
}
