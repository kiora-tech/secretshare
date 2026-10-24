<?php

declare(strict_types=1);

namespace App\Controller;

use App\Secret\RequestStore;
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

#[Route('/api/requests', format: 'json')]
final class RequestApiController
{
    use ApiResponses;

    private const string ID = '[A-Za-z0-9_-]{22}';

    public function __construct(
        private readonly RequestStore $requests,
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
        $body = $this->json($request) ?? [];
        $id = self::validId($body['id'] ?? null);
        $publicKey = Base64Url::decode($body['publicKey'] ?? null, RequestStore::PUBLIC_KEY_LENGTH);
        $note = Base64Url::decode($body['note'] ?? null, maxLength: RequestStore::MAX_NOTE);
        $inboxHash = Base64Url::decode($body['inboxHash'] ?? null, 32);
        $respondHash = Base64Url::decode($body['respondHash'] ?? null, 32);
        $ttl = $body['ttl'] ?? null;

        if (null === $id || null === $publicKey || null === $note || \strlen($note) < 29 || null === $inboxHash
            || null === $respondHash || !\in_array($ttl, SecretStore::TTLS, true)) {
            return $this->error('invalid_request', 400);
        }
        if ($this->requests->exists($id)) {
            return $this->error('id_taken', 409);
        }

        try {
            $expiresAt = $this->requests->create($id, $publicKey, $note, $inboxHash, $respondHash, $ttl);
        } catch (UniqueConstraintViolationException) {
            return $this->error('id_taken', 409);
        }

        return new JsonResponse(['id' => $id, 'expiresAt' => $expiresAt->format(\DATE_ATOM)], 201);
    }

    #[Route('/{id}', requirements: ['id' => self::ID], methods: ['GET'])]
    public function forResponder(string $id, Request $request): JsonResponse
    {
        if ($limited = $this->limited($this->readLimiter, $request)) {
            return $limited;
        }
        $data = $this->requests->forResponder($id);
        if (null === $data) {
            return $this->error('gone', 404);
        }

        return new JsonResponse([
            'publicKey' => Base64Url::encode($data['publicKey']),
            'note' => Base64Url::encode($data['note']),
            'expiresAt' => $data['expiresAt'],
        ]);
    }

    #[Route('/{id}/respond', requirements: ['id' => self::ID], methods: ['POST'])]
    public function respond(string $id, Request $request): JsonResponse
    {
        if ($limited = $this->limited($this->createLimiter, $request)) {
            return $limited;
        }
        // La preuve de réponse, tirée de R : sans le lien de demande, pas de réponse possible.
        $auth = Base64Url::decode($this->bearer($request), 32);
        $body = $this->json($request) ?? [];
        $kem = Base64Url::decode($body['kem'] ?? null, RequestStore::KEM_CIPHERTEXT_LENGTH);
        $ciphertext = Base64Url::decode($body['ciphertext'] ?? null, maxLength: SecretStore::MAX_CIPHERTEXT);
        if (null === $auth || null === $kem || null === $ciphertext || \strlen($ciphertext) < 29) {
            return $this->error('invalid_request', 400);
        }
        if ($limited = $this->limited($this->uploadLimiter, $request, max(1, intdiv(\strlen($ciphertext) + 65535, 65536)))) {
            return $limited;
        }
        if (!$this->quota->allows(\strlen($ciphertext))) {
            return $this->error('storage_full', 507);
        }

        // Mauvaise preuve ou demande close : la même réponse.
        return $this->requests->respond($id, $auth, $kem, $ciphertext)
            ? new JsonResponse(['answered' => true], 201)
            : $this->error('gone', 404);
    }

    /** L'état de la boîte, sans rien ouvrir : la page attend un geste humain avant d'ouvrir. */
    #[Route('/{id}/status', requirements: ['id' => self::ID], methods: ['GET'])]
    public function inboxStatus(string $id, Request $request): JsonResponse
    {
        if ($limited = $this->limited($this->readLimiter, $request)) {
            return $limited;
        }
        $auth = Base64Url::decode($this->bearer($request), 32);
        $status = null === $auth ? null : $this->requests->inboxStatus($id, $auth);

        return null === $status ? $this->error('gone', 404) : new JsonResponse($status);
    }

    #[Route('/{id}/open', requirements: ['id' => self::ID], methods: ['POST'])]
    public function open(string $id, Request $request): JsonResponse
    {
        if ($limited = $this->limited($this->readLimiter, $request)) {
            return $limited;
        }
        $auth = Base64Url::decode($this->bearer($request), 32);
        if (null === $auth) {
            return $this->error('invalid_request', 400);
        }

        $result = $this->requests->open($id, $auth);

        return match ($result['state']) {
            'opened' => new JsonResponse([
                'state' => 'opened',
                'kem' => Base64Url::encode($result['kem'] ?? ''),
                'ciphertext' => Base64Url::encode($result['ciphertext'] ?? ''),
                'answeredAt' => $result['answeredAt'] ?? null,
            ]),
            'pending' => new JsonResponse(['state' => 'pending', 'expiresAt' => $result['expiresAt'] ?? null]),
            // Mauvaise clé ou demande disparue : la même réponse, pour ne rien laisser deviner.
            default => $this->error('gone', 404),
        };
    }

    #[Route('/{id}', requirements: ['id' => self::ID], methods: ['DELETE'])]
    public function burn(string $id, Request $request): Response
    {
        if ($limited = $this->limited($this->readLimiter, $request)) {
            return $limited;
        }
        $auth = Base64Url::decode($this->bearer($request), 32);
        if (null === $auth || !$this->requests->burn($id, $auth)) {
            return $this->error('not_found', 404);
        }

        return new Response(status: 204);
    }
}
