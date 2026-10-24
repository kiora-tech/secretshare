<?php

declare(strict_types=1);

namespace App\Secret;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use Symfony\Component\Clock\ClockInterface;

/**
 * Un secret n'existe ici que chiffré. Le serveur ne le rend qu'à qui prouve détenir la clé
 * (l'empreinte de la clé d'accès dérivée dans le navigateur), et l'efface à la dernière vue.
 */
final class SecretStore
{
    public const array TTLS = [3600, 86400, 604800, 2592000];
    public const int MAX_VIEWS = 10;
    /** 10 Mio de fichiers, plus l'en-tête, le remplissage et l'enveloppe AES-GCM. */
    public const int MAX_CIPHERTEXT = 10_616_832;
    /** Au dixième essai faux (phrase de passe), le secret est détruit. */
    public const int MAX_FAILED_ATTEMPTS = 10;
    /** Préfixe de l'empreinte gardée dans retired_id, pour qu'un identifiant ne serve qu'une fois. */
    public const string RETIRED = 'secret/';

    public function __construct(
        private readonly Connection $db,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param array{alg: string, salt: string, m: int, t: int, p: int}|null $kdf
     * @param string|null                                                   $linkHash SHA-256 de la preuve de lien, exigée avec une phrase de passe
     */
    public function create(string $id, string $ciphertext, string $authHash, string $manageHash, ?array $kdf, ?string $linkHash, int $maxViews, int $ttl): \DateTimeImmutable
    {
        $now = $this->clock->now();
        $expiresAt = $now->modify(\sprintf('+%d seconds', $ttl));

        $this->db->insert('secret', [
            'id' => $id,
            'ciphertext' => $ciphertext,
            'auth_hash' => $authHash,
            'manage_hash' => $manageHash,
            'link_hash' => $linkHash,
            'kdf' => null === $kdf ? null : json_encode($kdf, \JSON_THROW_ON_ERROR),
            'max_views' => $maxViews,
            'size' => \strlen($ciphertext),
            'created_at' => $now->format(\DATE_ATOM),
            'expires_at' => $expiresAt->format(\DATE_ATOM),
        ], [
            'ciphertext' => ParameterType::LARGE_OBJECT,
            'auth_hash' => ParameterType::LARGE_OBJECT,
            'manage_hash' => ParameterType::LARGE_OBJECT,
            'link_hash' => ParameterType::LARGE_OBJECT,
        ]);

        return $expiresAt;
    }

    /**
     * Un identifiant déjà servi, même purgé, reste pris : sinon qui détient un vieux lien
     * pourrait y déposer un autre contenu, que le lien d'origine déchiffrerait comme le vrai.
     */
    public function exists(string $id): bool
    {
        return false !== $this->db->fetchOne(
            "SELECT 1 FROM secret WHERE id = ? UNION ALL SELECT 1 FROM retired_id WHERE id_hash = sha256(convert_to(?, 'UTF8'))",
            [$id, self::RETIRED.$id],
        );
    }

    /**
     * Ce qu'il faut au navigateur avant d'ouvrir : sans le chiffré, donc sans consommer de vue.
     *
     * @return array{kdf: array<string, mixed>|null, maxViews: int, viewsLeft: int, expiresAt: string}|null
     */
    public function meta(string $id): ?array
    {
        $row = $this->db->fetchAssociative(
            'SELECT kdf, max_views, views, expires_at FROM secret
             WHERE id = ? AND ciphertext IS NOT NULL AND expires_at > ?',
            [$id, $this->clock->now()->format(\DATE_ATOM)],
        );
        if (false === $row) {
            return null;
        }

        return [
            'kdf' => null === $row['kdf'] ? null : json_decode($row['kdf'], true, flags: \JSON_THROW_ON_ERROR),
            'maxViews' => (int) $row['max_views'],
            'viewsLeft' => (int) $row['max_views'] - (int) $row['views'],
            'expiresAt' => self::iso($row['expires_at']),
        ];
    }

    /**
     * Sans phrase de passe, une clé d'accès fausse veut seulement dire « pas de K » : K fait 256 bits,
     * il n'y a rien à freiner, donc rien n'est compté. Avec une phrase de passe, la preuve de lien
     * (tirée de K seul) passe d'abord : seul qui détient le lien peut user les dix essais.
     */
    public function reveal(string $id, string $auth, ?string $link = null): RevealResult
    {
        return $this->db->transactional(function (Connection $db) use ($id, $auth, $link): RevealResult {
            $row = $db->fetchAssociative(
                'SELECT ciphertext, auth_hash, link_hash, kdf, max_views, views, failed_attempts, expires_at
                 FROM secret WHERE id = ? FOR UPDATE',
                [$id],
            );
            $now = $this->clock->now();
            if (false === $row || null === $row['ciphertext'] || new \DateTimeImmutable($row['expires_at']) <= $now) {
                return RevealResult::gone();
            }

            $passphrase = null !== $row['kdf'];
            if ($passphrase && (null === $row['link_hash'] || null === $link
                || !hash_equals(self::bytes($row['link_hash']), hash('sha256', $link, true)))) {
                return RevealResult::mismatch();
            }

            if (!hash_equals(self::bytes($row['auth_hash']), hash('sha256', $auth, true))) {
                if (!$passphrase) {
                    return RevealResult::mismatch();
                }
                $failed = (int) $row['failed_attempts'] + 1;
                if ($failed >= self::MAX_FAILED_ATTEMPTS) {
                    $db->executeStatement(
                        "UPDATE secret SET failed_attempts = ?, ciphertext = NULL, burned_at = ?, burn_reason = 'attempts' WHERE id = ?",
                        [$failed, $now->format(\DATE_ATOM), $id],
                    );

                    return RevealResult::gone();
                }
                $db->executeStatement('UPDATE secret SET failed_attempts = ? WHERE id = ?', [$failed, $id]);

                return RevealResult::denied(self::MAX_FAILED_ATTEMPTS - $failed);
            }

            $views = (int) $row['views'] + 1;
            $last = $views >= (int) $row['max_views'];
            $db->executeStatement(
                'UPDATE secret SET views = ?, viewed_at = viewed_at || ?::jsonb,
                     ciphertext = CASE WHEN ? THEN NULL ELSE ciphertext END
                 WHERE id = ?',
                [$views, json_encode([$now->format(\DATE_ATOM)], \JSON_THROW_ON_ERROR), $last, $id],
                [ParameterType::INTEGER, ParameterType::STRING, ParameterType::BOOLEAN, ParameterType::STRING],
            );

            return RevealResult::revealed(self::bytes($row['ciphertext']), (int) $row['max_views'] - $views);
        });
    }

    /**
     * Le suivi de l'expéditeur, sans compte : qui détient le jeton de suivi voit les lectures.
     *
     * @return array{state: string, maxViews: int, views: int, viewedAt: list<string>, createdAt: string, expiresAt: string, burnedAt: string|null, burnReason: string|null}|null
     */
    public function status(string $id, string $manageToken): ?array
    {
        $row = $this->db->fetchAssociative(
            'SELECT manage_hash, ciphertext IS NOT NULL AS available, max_views, views, viewed_at,
                    created_at, expires_at, burned_at, burn_reason
             FROM secret WHERE id = ?',
            [$id],
        );
        if (false === $row || !hash_equals(self::bytes($row['manage_hash']), hash('sha256', $manageToken, true))) {
            return null;
        }

        $expired = new \DateTimeImmutable($row['expires_at']) <= $this->clock->now();
        $state = match (true) {
            null !== $row['burned_at'] => 'burned',
            !$row['available'] && (int) $row['views'] >= (int) $row['max_views'] => 'consumed',
            $expired => 'expired',
            default => 'active',
        };

        return [
            'state' => $state,
            'maxViews' => (int) $row['max_views'],
            'views' => (int) $row['views'],
            'viewedAt' => array_values(array_map(self::iso(...), json_decode($row['viewed_at'], true, flags: \JSON_THROW_ON_ERROR))),
            'createdAt' => self::iso($row['created_at']),
            'expiresAt' => self::iso($row['expires_at']),
            'burnedAt' => null === $row['burned_at'] ? null : self::iso($row['burned_at']),
            'burnReason' => null === $row['burn_reason'] ? null : (string) $row['burn_reason'],
        ];
    }

    public function burn(string $id, string $manageToken): bool
    {
        if (null === $this->status($id, $manageToken)) {
            return false;
        }
        $this->db->executeStatement(
            "UPDATE secret SET ciphertext = NULL, burned_at = COALESCE(burned_at, ?), burn_reason = COALESCE(burn_reason, 'sender') WHERE id = ?",
            [$this->clock->now()->format(\DATE_ATOM), $id],
        );

        return true;
    }

    /**
     * Une ligne vit jusqu'à son expiration, même lue : c'est elle qui sert l'accusé de lecture.
     * À la purge, l'identifiant laisse son empreinte dans retired_id, pour ne jamais resservir.
     */
    public function purgeExpired(): int
    {
        return (int) $this->db->transactional(function (Connection $db): int {
            $now = $this->clock->now()->format(\DATE_ATOM);
            $db->executeStatement(
                "INSERT INTO retired_id (id_hash)
                 SELECT sha256(convert_to(? || id, 'UTF8')) FROM secret WHERE expires_at <= ?
                 ON CONFLICT DO NOTHING",
                [self::RETIRED, $now],
            );

            return (int) $db->executeStatement('DELETE FROM secret WHERE expires_at <= ?', [$now]);
        });
    }

    /** pdo_pgsql rend les colonnes BYTEA sous forme de flux. */
    public static function bytes(mixed $value): string
    {
        return \is_resource($value) ? (string) stream_get_contents($value) : (string) $value;
    }

    private static function iso(string $timestamp): string
    {
        return new \DateTimeImmutable($timestamp)->setTimezone(new \DateTimeZone('UTC'))->format(\DATE_ATOM);
    }
}
