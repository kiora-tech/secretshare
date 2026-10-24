<?php

declare(strict_types=1);

namespace App\Controller;

use App\Secret\SecretStore;
use App\Secret\StorageQuota;
use App\Util\Base64Url;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\DependencyInjection\Attribute\Target;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/api/secrets', format: 'json')]
final class SecretApiController
{
    use ApiResponses;

    private const string ID = '[A-Za-z0-9_-]{22}';
    /** Les seuls réglages Argon2id acceptés : 64 Mio, 3 passes, parallélisme 1. */
    private const array KDF = ['alg' => 'argon2id', 'm' => 65536, 't' => 3, 'p' => 1];

    public function __construct(
        private readonly SecretStore $secrets,
        private readonly StorageQuota $quota,
        #[Target('create.limiter')] private readonly RateLimiterFactoryInterface $createLimiter,
        #[Target('read.limiter')] private readonly RateLimiterFactoryInterface $readLimiter,
        #[Target('upload.limiter')] private readonly RateLimiterFactoryInterface $uploadLimiter,
        #[Autowire('%kernel.secret%')] private readonly string $kernelSecret,
    ) {
    }

    #[Route('', methods: ['POST'])]
    public function create(Request $request): JsonResponse
    {
        if ($limited = $this->limited($this->createLimiter, $request)) {
            return $limited;
        }
        $body = $this->json($request);
        if (null === $body) {
            return $this->error('invalid_json', 400);
        }

        $id = self::validId($body['id'] ?? null);
        $ciphertext = Base64Url::decode($body['ciphertext'] ?? null, maxLength: SecretStore::MAX_CIPHERTEXT);
        $authHash = Base64Url::decode($body['authHash'] ?? null, 32);
        $manageHash = Base64Url::decode($body['manageHash'] ?? null, 32);
        $maxViews = $body['maxViews'] ?? null;
        $ttl = $body['ttl'] ?? null;
        $kdf = $this->kdf($body['kdf'] ?? null);
        // Avec une phrase de passe, la preuve de lien est obligatoire : c'est elle qui protège
        // les dix essais de qui ne connaît que l'identifiant.
        $linkHash = null === $kdf ? null : Base64Url::decode($body['linkHash'] ?? null, 32);

        if (null === $id || null === $authHash || null === $manageHash || false === $kdf
            || (null !== $kdf && null === $linkHash)
            || !\is_int($maxViews) || $maxViews < 1 || $maxViews > SecretStore::MAX_VIEWS
            || !\in_array($ttl, SecretStore::TTLS, true)) {
            return $this->error('invalid_request', 400);
        }
        if (null === $ciphertext) {
            $tooLarge = \is_string($body['ciphertext'] ?? null)
                && intdiv(\strlen($body['ciphertext']) * 3, 4) > SecretStore::MAX_CIPHERTEXT;

            return $tooLarge ? $this->error('too_large', 413) : $this->error('invalid_request', 400);
        }
        // Octet de version, IV de 12 octets, étiquette GCM de 16 octets : rien ne peut être plus court.
        if (\strlen($ciphertext) < 29) {
            return $this->error('invalid_request', 400);
        }
        if ($this->secrets->exists($id)) {
            return $this->error('id_taken', 409);
        }
        if ($limited = $this->limited($this->uploadLimiter, $request, self::uploadTokens($ciphertext))) {
            return $limited;
        }
        if (!$this->quota->allows(\strlen($ciphertext))) {
            return $this->error('storage_full', 507);
        }

        try {
            $expiresAt = $this->secrets->create($id, $ciphertext, $authHash, $manageHash, $kdf, $linkHash, $maxViews, $ttl);
        } catch (UniqueConstraintViolationException) {
            return $this->error('id_taken', 409);
        }

        return new JsonResponse(['id' => $id, 'expiresAt' => $expiresAt->format(\DATE_ATOM)], 201);
    }

    #[Route('/{id}', requirements: ['id' => self::ID], methods: ['GET'])]
    public function meta(string $id, Request $request): JsonResponse
    {
        if ($limited = $this->limited($this->readLimiter, $request)) {
            return $limited;
        }
        $meta = $this->secrets->meta($id);

        return null === $meta ? $this->error('gone', 404) : new JsonResponse($meta);
    }

    #[Route('/{id}/reveal', requirements: ['id' => self::ID], methods: ['POST'])]
    public function reveal(string $id, Request $request): JsonResponse
    {
        if ($limited = $this->limited($this->readLimiter, $request)) {
            return $limited;
        }
        $body = $this->json($request) ?? [];
        $auth = Base64Url::decode($body['auth'] ?? null, 32);
        $link = Base64Url::decode($body['link'] ?? null, 32);
        if (null === $auth || (isset($body['link']) && null === $link)) {
            return $this->error('invalid_request', 400);
        }

        $result = $this->secrets->reveal($id, $auth, $link);

        return match ($result->outcome) {
            'revealed' => new JsonResponse([
                'ciphertext' => Base64Url::encode((string) $result->ciphertext),
                'viewsLeft' => $result->left,
            ]),
            'denied' => $this->error('wrong_key', 403, ['attemptsLeft' => $result->left]),
            'mismatch' => $this->error('wrong_link', 403),
            default => $this->error('gone', 404),
        };
    }

    #[Route('/{id}/status', requirements: ['id' => self::ID], methods: ['GET'])]
    public function status(string $id, Request $request): JsonResponse
    {
        if ($limited = $this->limited($this->readLimiter, $request)) {
            return $limited;
        }
        $token = Base64Url::decode($this->bearer($request), 32);
        $status = null === $token ? null : $this->secrets->status($id, $token);

        return null === $status ? $this->error('not_found', 404) : new JsonResponse($status);
    }

    #[Route('/{id}', requirements: ['id' => self::ID], methods: ['DELETE'])]
    public function burn(string $id, Request $request): Response
    {
        if ($limited = $this->limited($this->readLimiter, $request)) {
            return $limited;
        }
        $token = Base64Url::decode($this->bearer($request), 32);
        if (null === $token || !$this->secrets->burn($id, $token)) {
            return $this->error('not_found', 404);
        }

        return new Response(status: 204);
    }

    /** Le quota d'envoi se compte par tranches de 64 Kio : un secret de 10 Mio en use 162. */
    private static function uploadTokens(string $ciphertext): int
    {
        return max(1, intdiv(\strlen($ciphertext) + 65535, 65536));
    }

    /**
     * @return array{alg: string, salt: string, m: int, t: int, p: int}|false|null false si invalide
     */
    private function kdf(mixed $kdf): array|false|null
    {
        if (null === $kdf) {
            return null;
        }
        if (!\is_array($kdf) || null === Base64Url::decode($kdf['salt'] ?? null, 16)) {
            return false;
        }
        foreach (self::KDF as $key => $value) {
            if (($kdf[$key] ?? null) !== $value) {
                return false;
            }
        }

        return ['alg' => 'argon2id', 'salt' => $kdf['salt'], 'm' => 65536, 't' => 3, 'p' => 1];
    }
}
