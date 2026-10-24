<?php

declare(strict_types=1);

namespace App\Secret;

final readonly class RevealResult
{
    private function __construct(
        public string $outcome,
        public ?string $ciphertext = null,
        public int $left = 0,
    ) {
    }

    public static function revealed(string $ciphertext, int $viewsLeft): self
    {
        return new self('revealed', $ciphertext, $viewsLeft);
    }

    /** Mauvaise clé d'accès, donc mauvaise phrase de passe : le secret reste intact. */
    public static function denied(int $attemptsLeft): self
    {
        return new self('denied', left: $attemptsLeft);
    }

    /** Le lien ne correspond pas au secret (mauvais K) : rien n'est compté. */
    public static function mismatch(): self
    {
        return new self('mismatch');
    }

    /** Lu, expiré, détruit, ou n'a jamais existé : on ne dit pas lequel. */
    public static function gone(): self
    {
        return new self('gone');
    }
}
