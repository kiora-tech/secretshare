<?php

declare(strict_types=1);

namespace App\Tests\Functional;

final class RequestApiTest extends ApiTestCase
{
    private string $id;
    private string $inbox;
    private string $respond;

    private function createRequest(int $ttl = 604800): int
    {
        $this->id = self::id();
        $this->inbox = random_bytes(32);
        $this->respond = random_bytes(32);
        [$status] = $this->api('POST', '/api/requests', [
            'id' => $this->id,
            'publicKey' => self::b64(random_bytes(1216)),
            'note' => self::b64(random_bytes(541)),
            'inboxHash' => self::hash($this->inbox),
            'respondHash' => self::hash($this->respond),
            'ttl' => $ttl,
        ]);

        return $status;
    }

    public function testRequestIsAnsweredOnceAndOpenedOnce(): void
    {
        self::assertSame(201, $this->createRequest());

        [$status, $body] = $this->api('POST', "/api/requests/{$this->id}/open", token: self::b64($this->inbox));
        self::assertSame(200, $status);
        self::assertSame('pending', $body['state']);

        [$status, $body] = $this->api('GET', "/api/requests/{$this->id}");
        self::assertSame(200, $status);
        self::assertSame(1216, \strlen((string) \App\Util\Base64Url::decode($body['publicKey'])));

        [$status, $body] = $this->api('GET', "/api/requests/{$this->id}/status", token: self::b64($this->inbox));
        self::assertSame(200, $status);
        self::assertSame('pending', $body['state']);

        $kem = random_bytes(1120);
        $ciphertext = random_bytes(300);
        $answer = ['kem' => self::b64($kem), 'ciphertext' => self::b64($ciphertext)];
        [$status] = $this->api('POST', "/api/requests/{$this->id}/respond", $answer);
        self::assertSame(400, $status, 'Répondre exige la preuve tirée du lien de demande');
        [$status] = $this->api('POST', "/api/requests/{$this->id}/respond", $answer, token: self::b64(random_bytes(32)));
        self::assertSame(404, $status, 'L\'identifiant seul ne permet pas de répondre');
        [$status] = $this->api('GET', "/api/requests/{$this->id}");
        self::assertSame(200, $status, 'Une fausse réponse ne prend pas la place');

        [$status] = $this->api('POST', "/api/requests/{$this->id}/respond", $answer, token: self::b64($this->respond));
        self::assertSame(201, $status);
        [$status] = $this->api('POST', "/api/requests/{$this->id}/respond", $answer, token: self::b64($this->respond));
        self::assertSame(404, $status, 'Une demande ne prend qu\'une réponse');
        [$status] = $this->api('GET', "/api/requests/{$this->id}");
        self::assertSame(404, $status, 'Une demande répondue ne se montre plus au correspondant');

        // L'état de la boîte se lit sans rien consommer, autant de fois qu'on veut.
        for ($i = 0; $i < 2; ++$i) {
            [$status, $body] = $this->api('GET', "/api/requests/{$this->id}/status", token: self::b64($this->inbox));
            self::assertSame(200, $status);
            self::assertSame('answered', $body['state']);
        }
        [$status] = $this->api('GET', "/api/requests/{$this->id}/status", token: self::b64(random_bytes(32)));
        self::assertSame(404, $status);

        [$status] = $this->api('POST', "/api/requests/{$this->id}/open", token: self::b64(random_bytes(32)));
        self::assertSame(404, $status);

        [$status, $body] = $this->api('POST', "/api/requests/{$this->id}/open", token: self::b64($this->inbox));
        self::assertSame(200, $status);
        self::assertSame('opened', $body['state']);
        self::assertSame(self::b64($kem), $body['kem']);
        self::assertSame(self::b64($ciphertext), $body['ciphertext']);

        [$status] = $this->api('POST', "/api/requests/{$this->id}/open", token: self::b64($this->inbox));
        self::assertSame(404, $status, 'La réponse ne se lit qu\'une fois');
        [$status] = $this->api('GET', "/api/requests/{$this->id}/status", token: self::b64($this->inbox));
        self::assertSame(404, $status);
    }

    public function testRequesterCanCancel(): void
    {
        $this->createRequest();
        [$status] = $this->api('DELETE', "/api/requests/{$this->id}", token: self::b64($this->inbox));
        self::assertSame(204, $status);
        [$status] = $this->api('POST', "/api/requests/{$this->id}/respond", ['kem' => self::b64(random_bytes(1120)), 'ciphertext' => self::b64(random_bytes(100))], token: self::b64($this->respond));
        self::assertSame(404, $status);
    }

    public function testRejectsAPublicKeyOfTheWrongSize(): void
    {
        [$status] = $this->api('POST', '/api/requests', [
            'id' => self::id(), 'publicKey' => self::b64(random_bytes(1184)), 'note' => self::b64(random_bytes(541)),
            'inboxHash' => self::hash('x'), 'respondHash' => self::hash('y'), 'ttl' => 3600,
        ]);
        self::assertSame(400, $status);
    }

    public function testRejectsARequestWithoutRespondProof(): void
    {
        [$status] = $this->api('POST', '/api/requests', [
            'id' => self::id(), 'publicKey' => self::b64(random_bytes(1216)), 'note' => self::b64(random_bytes(541)),
            'inboxHash' => self::hash('x'), 'ttl' => 3600,
        ]);
        self::assertSame(400, $status);
    }

    public function testPurgeDeletesExpiredRows(): void
    {
        $this->createRequest(ttl: 3600);
        static::mockTime('+2 hours');

        self::assertStringContainsString('1 demande(s)', $this->purge());
        [$status] = $this->api('POST', "/api/requests/{$this->id}/open", token: self::b64($this->inbox));
        self::assertSame(404, $status);

        // Le même identifiant ne peut pas resservir : un vieux lien de demande ne serait plus le sien.
        [$status] = $this->api('POST', '/api/requests', [
            'id' => $this->id, 'publicKey' => self::b64(random_bytes(1216)), 'note' => self::b64(random_bytes(541)),
            'inboxHash' => self::hash('x'), 'respondHash' => self::hash('y'), 'ttl' => 3600,
        ]);
        self::assertSame(409, $status);
    }
}
