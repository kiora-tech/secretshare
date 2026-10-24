<?php

declare(strict_types=1);

namespace App\Tests\Functional;

final class SecretApiTest extends ApiTestCase
{
    private string $id;
    private string $auth;
    private string $manage;
    private string $link;
    private string $ciphertext;

    private const array KDF = ['alg' => 'argon2id', 'm' => 65536, 't' => 3, 'p' => 1];

    protected function setUp(): void
    {
        parent::setUp();
        $this->link = random_bytes(32);
    }

    /** @param array<string, mixed> $overrides */
    private function createSecret(int $maxViews = 1, int $ttl = 3600, array $overrides = []): int
    {
        $this->id = self::id();
        $this->auth = random_bytes(32);
        $this->manage = random_bytes(32);
        $this->ciphertext = random_bytes(200);

        [$status] = $this->api('POST', '/api/secrets', $overrides + [
            'id' => $this->id,
            'ciphertext' => self::b64($this->ciphertext),
            'authHash' => self::hash($this->auth),
            'manageHash' => self::hash($this->manage),
            'kdf' => null,
            'maxViews' => $maxViews,
            'ttl' => $ttl,
        ]);

        return $status;
    }

    public function testSecretIsReadableExactlyMaxViewsTimes(): void
    {
        self::assertSame(201, $this->createSecret(maxViews: 2));

        [$status, $meta] = $this->api('GET', "/api/secrets/{$this->id}");
        self::assertSame(200, $status);
        self::assertSame(2, $meta['viewsLeft'], 'Lire les métadonnées ne consomme pas de vue');

        [$status, $body] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64($this->auth)]);
        self::assertSame(200, $status);
        self::assertSame(self::b64($this->ciphertext), $body['ciphertext']);
        self::assertSame(1, $body['viewsLeft']);

        [$status, $body] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64($this->auth)]);
        self::assertSame(200, $status);
        self::assertSame(0, $body['viewsLeft']);

        [$status] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64($this->auth)]);
        self::assertSame(404, $status);
    }

    public function testCiphertextIsDeletedAtTheLastView(): void
    {
        $this->createSecret();
        $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64($this->auth)]);

        self::assertNull($this->db()->fetchOne('SELECT ciphertext FROM secret WHERE id = ?', [$this->id]));
    }

    public function testWrongKeyWithoutPassphraseIsRefusedButNeverCounted(): void
    {
        $this->createSecret();

        // Sans phrase de passe, une clé fausse veut dire « pas de K » : qui ne connaît que
        // l'identifiant ne doit pas pouvoir détruire le secret à coups d'essais.
        for ($i = 0; $i < 12; ++$i) {
            [$status, $body] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64(random_bytes(32))]);
            self::assertSame(403, $status);
            self::assertSame('wrong_link', $body['error']);
            self::assertArrayNotHasKey('ciphertext', $body);
        }

        [$status, $body] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64($this->auth)]);
        self::assertSame(200, $status, 'Le destinataire lit toujours son secret');
        self::assertSame(self::b64($this->ciphertext), $body['ciphertext']);
    }

    public function testPassphraseAttemptsCountOnlyWithTheLinkProof(): void
    {
        $kdf = self::KDF + ['salt' => self::b64(random_bytes(16))];
        self::assertSame(201, $this->createSecret(overrides: ['kdf' => $kdf, 'linkHash' => self::hash($this->link)]));

        // L'identifiant seul : ni comparé, ni compté.
        for ($i = 0; $i < 12; ++$i) {
            [$status, $body] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64(random_bytes(32))]);
            self::assertSame(403, $status);
            self::assertSame('wrong_link', $body['error']);
        }
        [$status, $body] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64($this->auth), 'link' => self::b64(random_bytes(32))]);
        self::assertSame('wrong_link', $body['error'], 'Une bonne clé d\'accès sans la preuve de lien ne passe pas');

        // Avec le lien, chaque mauvaise phrase compte, et la dixième détruit.
        [$status, $body] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64(random_bytes(32)), 'link' => self::b64($this->link)]);
        self::assertSame(403, $status);
        self::assertSame('wrong_key', $body['error']);
        self::assertSame(9, $body['attemptsLeft']);
        for ($i = 0; $i < 9; ++$i) {
            $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64(random_bytes(32)), 'link' => self::b64($this->link)]);
        }
        [$status] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64($this->auth), 'link' => self::b64($this->link)]);
        self::assertSame(404, $status, 'Après dix essais faux, même la bonne phrase ne rend plus rien');

        [, $status] = $this->api('GET', "/api/secrets/{$this->id}/status", token: self::b64($this->manage));
        self::assertSame('burned', $status['state']);
        self::assertSame('attempts', $status['burnReason']);
    }

    public function testPassphraseSecretOpensWithLinkProofAndAuth(): void
    {
        $kdf = self::KDF + ['salt' => self::b64(random_bytes(16))];
        $this->createSecret(overrides: ['kdf' => $kdf, 'linkHash' => self::hash($this->link)]);

        [$status, $body] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64($this->auth), 'link' => self::b64($this->link)]);
        self::assertSame(200, $status);
        self::assertSame(self::b64($this->ciphertext), $body['ciphertext']);
    }

    public function testExpiredSecretIsGone(): void
    {
        $this->createSecret(ttl: 3600);
        static::mockTime('+3601 seconds');

        [$status] = $this->api('GET', "/api/secrets/{$this->id}");
        self::assertSame(404, $status);
        [$status] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64($this->auth)]);
        self::assertSame(404, $status);
    }

    public function testSenderTracksReadsAndCanBurn(): void
    {
        $this->createSecret(maxViews: 3);
        $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64($this->auth)]);

        [$status, $body] = $this->api('GET', "/api/secrets/{$this->id}/status", token: self::b64($this->manage));
        self::assertSame(200, $status);
        self::assertSame('active', $body['state']);
        self::assertSame(1, $body['views']);
        self::assertCount(1, $body['viewedAt']);

        [$status] = $this->api('GET', "/api/secrets/{$this->id}/status", token: self::b64(random_bytes(32)));
        self::assertSame(404, $status, 'Le suivi exige le jeton');

        [$status] = $this->api('DELETE', "/api/secrets/{$this->id}", token: self::b64($this->manage));
        self::assertSame(204, $status);
        [$status] = $this->api('POST', "/api/secrets/{$this->id}/reveal", ['auth' => self::b64($this->auth)]);
        self::assertSame(404, $status);
    }

    public function testRejectsInvalidInput(): void
    {
        self::assertSame(400, $this->createSecret(ttl: 999));
        self::assertSame(400, $this->createSecret(maxViews: 11));
        self::assertSame(400, $this->createSecret(overrides: ['authHash' => self::b64(random_bytes(16))]));
        self::assertSame(400, $this->createSecret(overrides: ['kdf' => ['alg' => 'argon2id', 'salt' => self::b64(random_bytes(16)), 'm' => 1024, 't' => 1, 'p' => 1]]));
        self::assertSame(400, $this->createSecret(overrides: ['ciphertext' => self::b64(random_bytes(10))]));
        self::assertSame(400, $this->createSecret(overrides: ['kdf' => self::KDF + ['salt' => self::b64(random_bytes(16))]]), 'Une phrase de passe exige la preuve de lien');
        self::assertSame(400, $this->createSecret(overrides: ['id' => self::id()."\n"]), 'Un saut de ligne après l\'identifiant est refusé');
        self::assertSame(201, $this->createSecret(overrides: ['kdf' => self::KDF + ['salt' => self::b64(random_bytes(16))], 'linkHash' => self::hash('l')]));
    }

    public function testAnIdIsNeverReusedAfterPurge(): void
    {
        $this->createSecret(ttl: 3600);
        static::mockTime('+2 hours');
        self::assertStringContainsString('1 secret(s)', $this->purge());

        [$status] = $this->api('POST', '/api/secrets', [
            'id' => $this->id, 'ciphertext' => self::b64(random_bytes(100)), 'authHash' => self::hash('a'),
            'manageHash' => self::hash('b'), 'kdf' => null, 'maxViews' => 1, 'ttl' => 3600,
        ]);
        self::assertSame(409, $status, 'Un vieux lien ne peut pas être repris après la purge');
    }

    public function testRequestsFromOtherSitesAreRefusedBeforeCounting(): void
    {
        $this->createSecret();

        [$status, $body] = $this->api('GET', "/api/secrets/{$this->id}", server: ['HTTP_SEC_FETCH_SITE' => 'cross-site']);
        self::assertSame(403, $status);
        self::assertSame('cross_site', $body['error']);

        [$status, $body] = $this->api('POST', '/api/secrets', ['id' => self::id()], server: ['CONTENT_TYPE' => 'text/plain', 'HTTP_SEC_FETCH_SITE' => 'none']);
        self::assertSame(400, $status, 'Un POST sans JSON ni Authorization est refusé avant d\'être compté');
        self::assertSame('invalid_json', $body['error']);
    }

    public function testStorageLimitRefusesNewSecrets(): void
    {
        // STORAGE_LIMIT_BYTES vaut 1 Mio dans .env.test.
        $this->id = self::id();
        [$status, $body] = $this->api('POST', '/api/secrets', [
            'id' => $this->id, 'ciphertext' => self::b64(random_bytes(1_200_000)), 'authHash' => self::hash('a'),
            'manageHash' => self::hash('b'), 'kdf' => null, 'maxViews' => 1, 'ttl' => 3600,
        ]);
        self::assertSame(507, $status);
        self::assertSame('storage_full', $body['error']);
    }

    public function testRefusesAnIdAlreadyTaken(): void
    {
        $this->createSecret();
        [$status] = $this->api('POST', '/api/secrets', [
            'id' => $this->id, 'ciphertext' => self::b64(random_bytes(100)), 'authHash' => self::hash('a'),
            'manageHash' => self::hash('b'), 'kdf' => null, 'maxViews' => 1, 'ttl' => 3600,
        ]);
        self::assertSame(409, $status);
    }

    public function testSecretPagesAreNeverCachedNorIndexed(): void
    {
        $this->client->request('GET', '/s/'.self::id());
        $response = $this->client->getResponse();

        self::assertSame(200, $response->getStatusCode());
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        self::assertStringContainsString('noindex', (string) $response->headers->get('X-Robots-Tag'));
        self::assertMatchesRegularExpression("/script-src 'self' 'nonce-[\\w-]+'/", (string) $response->headers->get('Content-Security-Policy'));
    }
}
