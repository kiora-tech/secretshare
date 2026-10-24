<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use App\Util\Base64Url;
use Doctrine\DBAL\Connection;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Clock\Test\ClockSensitiveTrait;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Base de test : une vraie base Postgres (secretshare_test), vidée avant chaque test.
 * Les octets chiffrés sont aléatoires : le chiffrement se teste dans tests/e2e, ici on teste
 * ce que le serveur promet (lecture unique, preuve d'accès, expiration, destruction).
 */
abstract class ApiTestCase extends WebTestCase
{
    use ClockSensitiveTrait;

    protected KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = static::createClient();
        static::mockTime('2026-10-23 12:00:00');
        $this->db()->executeStatement('TRUNCATE secret, secret_request, retired_id');
    }

    protected function db(): Connection
    {
        $db = static::getContainer()->get(Connection::class);
        \assert($db instanceof Connection);

        return $db;
    }

    /**
     * @param array<string, mixed>|null $body
     * @param array<string, string>     $server en-têtes en plus, ou à la place des valeurs par défaut
     *
     * @return array{0: int, 1: array<string, mixed>}
     */
    protected function api(string $method, string $uri, ?array $body = null, ?string $token = null, array $server = []): array
    {
        $server += ['CONTENT_TYPE' => 'application/json', 'HTTP_ACCEPT' => 'application/json', 'HTTP_SEC_FETCH_SITE' => 'same-origin'];
        if (null !== $token) {
            $server['HTTP_AUTHORIZATION'] = 'Bearer '.$token;
        }
        $this->client->request($method, $uri, server: $server, content: null === $body ? null : json_encode($body, \JSON_THROW_ON_ERROR));
        $response = $this->client->getResponse();
        $content = (string) $response->getContent();

        $data = '' === $content ? [] : json_decode($content, true);

        return [$response->getStatusCode(), \is_array($data) ? $data : []];
    }

    protected static function id(): string
    {
        return Base64Url::encode(random_bytes(16));
    }

    protected static function b64(string $bytes): string
    {
        return Base64Url::encode($bytes);
    }

    protected static function hash(string $bytes): string
    {
        return Base64Url::encode(hash('sha256', $bytes, true));
    }

    protected function purge(): string
    {
        self::assertNotNull(static::$kernel);
        $tester = new CommandTester(new Application(static::$kernel)->find('app:purge'));
        $tester->execute([]);

        return $tester->getDisplay();
    }
}
