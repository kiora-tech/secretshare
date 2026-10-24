<?php

declare(strict_types=1);

namespace App\Secret;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use Symfony\Component\Clock\ClockInterface;

/**
 * La demande de secret, à l'envers du lien : le demandeur publie une clé publique X-Wing
 * (ML-KEM-768 + X25519), son correspondant chiffre pour elle, et seul le demandeur, qui garde
 * la clé privée dans le fragment de son lien de réception, peut ouvrir la réponse.
 */
final class RequestStore
{
    public const int PUBLIC_KEY_LENGTH = 1216;
    public const int KEM_CIPHERTEXT_LENGTH = 1120;
    /** La note du demandeur, chiffrée : 1 000 caractères au plus, remplis par paliers de 512 octets. */
    public const int MAX_NOTE = 8192;
    public const string RETIRED = 'request/';

    public function __construct(
        private readonly Connection $db,
        private readonly ClockInterface $clock,
    ) {
    }

    /**
     * @param string $respondHash SHA-256 de la preuve de réponse tirée de R : seul le lien de demande permet de répondre
     */
    public function create(string $id, string $publicKey, string $note, string $inboxHash, string $respondHash, int $ttl): \DateTimeImmutable
    {
        $now = $this->clock->now();
        $expiresAt = $now->modify(\sprintf('+%d seconds', $ttl));

        $this->db->insert('secret_request', [
            'id' => $id,
            'public_key' => $publicKey,
            'note' => $note,
            'inbox_hash' => $inboxHash,
            'respond_hash' => $respondHash,
            'created_at' => $now->format(\DATE_ATOM),
            'expires_at' => $expiresAt->format(\DATE_ATOM),
        ], [
            'public_key' => ParameterType::LARGE_OBJECT,
            'note' => ParameterType::LARGE_OBJECT,
            'inbox_hash' => ParameterType::LARGE_OBJECT,
            'respond_hash' => ParameterType::LARGE_OBJECT,
        ]);

        return $expiresAt;
    }

    /** Comme pour les secrets : un identifiant purgé reste pris (voir SecretStore::exists). */
    public function exists(string $id): bool
    {
        return false !== $this->db->fetchOne(
            "SELECT 1 FROM secret_request WHERE id = ? UNION ALL SELECT 1 FROM retired_id WHERE id_hash = sha256(convert_to(?, 'UTF8'))",
            [$id, self::RETIRED.$id],
        );
    }

    /**
     * Ce dont le correspondant a besoin pour répondre.
     *
     * @return array{publicKey: string, note: string, expiresAt: string}|null
     */
    public function forResponder(string $id): ?array
    {
        $row = $this->db->fetchAssociative(
            'SELECT public_key, note, expires_at FROM secret_request
             WHERE id = ? AND expires_at > ? AND answered_at IS NULL AND burned_at IS NULL',
            [$id, $this->clock->now()->format(\DATE_ATOM)],
        );
        if (false === $row) {
            return null;
        }

        return [
            'publicKey' => SecretStore::bytes($row['public_key']),
            'note' => SecretStore::bytes($row['note']),
            'expiresAt' => new \DateTimeImmutable($row['expires_at'])->setTimezone(new \DateTimeZone('UTC'))->format(\DATE_ATOM),
        ];
    }

    /**
     * Une demande n'accepte qu'une réponse, et seulement de qui détient le lien de demande :
     * l'identifiant seul (vu dans un chemin d'URL) ne suffit pas à prendre la place.
     */
    public function respond(string $id, string $respondAuth, string $kem, string $ciphertext): bool
    {
        return $this->db->transactional(function (Connection $db) use ($id, $respondAuth, $kem, $ciphertext): bool {
            $now = $this->clock->now();
            $row = $db->fetchAssociative(
                'SELECT respond_hash, expires_at, answered_at, burned_at FROM secret_request WHERE id = ? FOR UPDATE',
                [$id],
            );
            if (false === $row || null === $row['respond_hash']
                || !hash_equals(SecretStore::bytes($row['respond_hash']), hash('sha256', $respondAuth, true))
                || null !== $row['answered_at'] || null !== $row['burned_at']
                || new \DateTimeImmutable($row['expires_at']) <= $now) {
                return false;
            }
            $db->executeStatement(
                'UPDATE secret_request SET response_kem = ?, response_ciphertext = ?, answered_at = ? WHERE id = ?',
                [$kem, $ciphertext, $now->format(\DATE_ATOM), $id],
                [ParameterType::LARGE_OBJECT, ParameterType::LARGE_OBJECT, ParameterType::STRING, ParameterType::STRING],
            );

            return true;
        });
    }

    /**
     * L'état de la boîte, sans rien consommer : la page attend un geste humain avant d'ouvrir.
     *
     * @return array{state: 'pending'|'answered', expiresAt: string}|null null si la demande est close ou la clé fausse
     */
    public function inboxStatus(string $id, string $inboxAuth): ?array
    {
        $row = $this->db->fetchAssociative(
            'SELECT inbox_hash, answered_at, opened_at, burned_at, expires_at FROM secret_request WHERE id = ?',
            [$id],
        );
        if (false === $row || !hash_equals(SecretStore::bytes($row['inbox_hash']), hash('sha256', $inboxAuth, true))
            || null !== $row['opened_at'] || null !== $row['burned_at']
            || new \DateTimeImmutable($row['expires_at']) <= $this->clock->now()) {
            return null;
        }

        return [
            'state' => null === $row['answered_at'] ? 'pending' : 'answered',
            'expiresAt' => new \DateTimeImmutable($row['expires_at'])->setTimezone(new \DateTimeZone('UTC'))->format(\DATE_ATOM),
        ];
    }

    /**
     * Le demandeur ouvre sa boîte. La réponse n'est rendue qu'une fois, puis effacée.
     *
     * @return array{state: 'pending'|'opened'|'gone'|'denied', kem?: string, ciphertext?: string, answeredAt?: string, expiresAt?: string}
     */
    public function open(string $id, string $inboxAuth): array
    {
        return $this->db->transactional(function (Connection $db) use ($id, $inboxAuth): array {
            $now = $this->clock->now();
            $row = $db->fetchAssociative(
                'SELECT inbox_hash, response_kem, response_ciphertext, answered_at, opened_at, burned_at, expires_at
                 FROM secret_request WHERE id = ? FOR UPDATE',
                [$id],
            );
            if (false === $row) {
                return ['state' => 'gone'];
            }
            if (!hash_equals(SecretStore::bytes($row['inbox_hash']), hash('sha256', $inboxAuth, true))) {
                return ['state' => 'denied'];
            }
            if (null !== $row['opened_at'] || null !== $row['burned_at'] || new \DateTimeImmutable($row['expires_at']) <= $now) {
                return ['state' => 'gone'];
            }
            if (null === $row['answered_at']) {
                return [
                    'state' => 'pending',
                    'expiresAt' => new \DateTimeImmutable($row['expires_at'])->setTimezone(new \DateTimeZone('UTC'))->format(\DATE_ATOM),
                ];
            }

            $db->executeStatement(
                'UPDATE secret_request SET response_kem = NULL, response_ciphertext = NULL, opened_at = ? WHERE id = ?',
                [$now->format(\DATE_ATOM), $id],
            );

            return [
                'state' => 'opened',
                'kem' => SecretStore::bytes($row['response_kem']),
                'ciphertext' => SecretStore::bytes($row['response_ciphertext']),
                'answeredAt' => new \DateTimeImmutable($row['answered_at'])->setTimezone(new \DateTimeZone('UTC'))->format(\DATE_ATOM),
            ];
        });
    }

    public function burn(string $id, string $inboxAuth): bool
    {
        $hash = $this->db->fetchOne('SELECT inbox_hash FROM secret_request WHERE id = ?', [$id]);
        if (false === $hash || !hash_equals(SecretStore::bytes($hash), hash('sha256', $inboxAuth, true))) {
            return false;
        }
        $this->db->executeStatement(
            'UPDATE secret_request SET response_kem = NULL, response_ciphertext = NULL, burned_at = COALESCE(burned_at, ?) WHERE id = ?',
            [$this->clock->now()->format(\DATE_ATOM), $id],
        );

        return true;
    }

    public function purgeExpired(): int
    {
        return (int) $this->db->transactional(function (Connection $db): int {
            $now = $this->clock->now()->format(\DATE_ATOM);
            $db->executeStatement(
                "INSERT INTO retired_id (id_hash)
                 SELECT sha256(convert_to(? || id, 'UTF8')) FROM secret_request WHERE expires_at <= ?
                 ON CONFLICT DO NOTHING",
                [self::RETIRED, $now],
            );

            return (int) $db->executeStatement('DELETE FROM secret_request WHERE expires_at <= ?', [$now]);
        });
    }
}
