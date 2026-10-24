<?php

declare(strict_types=1);

namespace App\Tests\Unit;

use App\Util\Base64Url;
use PHPUnit\Framework\TestCase;

final class Base64UrlTest extends TestCase
{
    public function testRoundTripWithoutPadding(): void
    {
        $bytes = random_bytes(32);
        $encoded = Base64Url::encode($bytes);

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $encoded);
        self::assertSame($bytes, Base64Url::decode($encoded, 32));
    }

    public function testRejectsWrongLength(): void
    {
        self::assertNull(Base64Url::decode(Base64Url::encode(random_bytes(31)), 32));
    }

    public function testRejectsAnythingButStrictBase64Url(): void
    {
        self::assertNull(Base64Url::decode('abc+/'));
        self::assertNull(Base64Url::decode('YWJj='));
        self::assertNull(Base64Url::decode(''));
        self::assertNull(Base64Url::decode(['array']));
        // Bits de queue non nuls : « YWJk » et « YWJl » ne doivent pas désigner les mêmes octets.
        self::assertNull(Base64Url::decode('YWJjZB'));
    }

    public function testRejectsOversizedValueBeforeDecoding(): void
    {
        self::assertNull(Base64Url::decode(Base64Url::encode(random_bytes(100)), maxLength: 99));
    }
}
