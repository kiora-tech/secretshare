<?php

declare(strict_types=1);

namespace App\Twig;

use App\EventSubscriber\SecurityHeadersSubscriber;
use Symfony\Component\HttpFoundation\RequestStack;
use Twig\Attribute\AsTwigFunction;

final class CspExtension
{
    public function __construct(private readonly RequestStack $requestStack)
    {
    }

    #[AsTwigFunction('csp_nonce')]
    public function nonce(): string
    {
        return (string) $this->requestStack->getMainRequest()?->attributes->get(SecurityHeadersSubscriber::NONCE_ATTRIBUTE);
    }
}
