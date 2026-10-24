<?php

declare(strict_types=1);

namespace App\Secret;

use Doctrine\DBAL\Connection;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Le cluster Postgres est partagé avec d'autres services : au-delà de ce volume de chiffré
 * stocké, plus rien n'entre. Le contrôle n'est pas atomique, il peut être dépassé d'une
 * poignée de requêtes simultanées ; il borne l'ordre de grandeur, pas l'octet.
 */
final class StorageQuota
{
    public function __construct(
        private readonly Connection $db,
        #[Autowire(env: 'int:STORAGE_LIMIT_BYTES')] private readonly int $limit,
    ) {
    }

    public function allows(int $bytes): bool
    {
        $stored = (int) $this->db->fetchOne(
            'SELECT (SELECT COALESCE(SUM(size), 0) FROM secret WHERE ciphertext IS NOT NULL)
                  + (SELECT COALESCE(SUM(octet_length(response_ciphertext)), 0) FROM secret_request WHERE response_ciphertext IS NOT NULL)',
        );

        return $stored + $bytes <= $this->limit;
    }
}
