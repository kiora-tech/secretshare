<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Le serveur ne garde que du chiffré et des empreintes : ni texte clair, ni clé, ni adresse IP.
 */
final class Version20261023200000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Secrets à lecture limitée et demandes de secret';
    }

    public function up(Schema $schema): void
    {
        $this->addSql(<<<'SQL'
            CREATE TABLE secret (
                id VARCHAR(22) PRIMARY KEY,
                ciphertext BYTEA,
                auth_hash BYTEA NOT NULL,
                manage_hash BYTEA NOT NULL,
                kdf JSONB,
                max_views SMALLINT NOT NULL,
                views SMALLINT NOT NULL DEFAULT 0,
                failed_attempts SMALLINT NOT NULL DEFAULT 0,
                size INTEGER NOT NULL,
                viewed_at JSONB NOT NULL DEFAULT '[]',
                created_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                burned_at TIMESTAMPTZ,
                burn_reason VARCHAR(16)
            )
            SQL);
        $this->addSql('CREATE INDEX secret_expires_at ON secret (expires_at)');

        $this->addSql(<<<'SQL'
            CREATE TABLE secret_request (
                id VARCHAR(22) PRIMARY KEY,
                public_key BYTEA NOT NULL,
                note BYTEA NOT NULL,
                inbox_hash BYTEA NOT NULL,
                response_kem BYTEA,
                response_ciphertext BYTEA,
                failed_attempts SMALLINT NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                answered_at TIMESTAMPTZ,
                opened_at TIMESTAMPTZ,
                burned_at TIMESTAMPTZ
            )
            SQL);
        $this->addSql('CREATE INDEX secret_request_expires_at ON secret_request (expires_at)');

        // Schéma attendu par le DoctrineDbalAdapter de Symfony (compteurs des limites de débit).
        $this->addSql(<<<'SQL'
            CREATE TABLE cache_items (
                item_id VARCHAR(255) PRIMARY KEY,
                item_data BYTEA NOT NULL,
                item_lifetime INTEGER,
                item_time INTEGER NOT NULL
            )
            SQL);
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE cache_items');
        $this->addSql('DROP TABLE secret_request');
        $this->addSql('DROP TABLE secret');
    }
}
