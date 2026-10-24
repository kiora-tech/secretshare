<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Suites de l'audit de sécurité du 23/10/2026 :
 * - un identifiant n'est jamais réattribué (retired_id garde l'empreinte des identifiants purgés) ;
 * - répondre à une demande exige une preuve tirée de R (respond_hash) ;
 * - un secret à phrase de passe garde une preuve de K seule (link_hash), pour ne compter
 *   les essais que de qui détient le lien.
 */
final class Version20261024090000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Identifiants retirés, preuve de réponse, preuve de lien';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('CREATE TABLE retired_id (id_hash BYTEA PRIMARY KEY)');
        $this->addSql('ALTER TABLE secret ADD link_hash BYTEA');
        $this->addSql('ALTER TABLE secret_request ADD respond_hash BYTEA');
        $this->addSql('ALTER TABLE secret_request DROP COLUMN failed_attempts');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('ALTER TABLE secret_request ADD failed_attempts SMALLINT NOT NULL DEFAULT 0');
        $this->addSql('ALTER TABLE secret_request DROP COLUMN respond_hash');
        $this->addSql('ALTER TABLE secret DROP COLUMN link_hash');
        $this->addSql('DROP TABLE retired_id');
    }
}
