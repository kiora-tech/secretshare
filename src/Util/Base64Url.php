<?php

declare(strict_types=1);

namespace App\Util;

/**
 * Le navigateur encode tout en base64url sans remplissage (RFC 4648 §5) : identifiants, clés,
 * empreintes et chiffrés passent ainsi dans une URL comme dans du JSON.
 */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Rend null pour tout ce qui n'est pas du base64url strict, ou n'a pas la longueur attendue.
     */
    public static function decode(mixed $value, ?int $length = null, int $maxLength = \PHP_INT_MAX): ?string
    {
        if (!\is_string($value) || '' === $value || !preg_match('/^[A-Za-z0-9_-]+$/', $value)) {
            return null;
        }
        // Avant de décoder : un chiffré trop long ne doit pas être alloué pour rien, et une valeur
        // de longueur fixe (clé, jeton, empreinte) se reconnaît à sa longueur encodée.
        if (intdiv(\strlen($value) * 3, 4) > $maxLength
            || (null !== $length && \strlen($value) !== intdiv(4 * $length + 2, 3))) {
            return null;
        }
        $bytes = base64_decode(strtr($value, '-_', '+/'), true);
        if (false === $bytes || self::encode($bytes) !== $value) {
            return null;
        }
        if (null !== $length && \strlen($bytes) !== $length) {
            return null;
        }

        return \strlen($bytes) > $maxLength ? null : $bytes;
    }
}
