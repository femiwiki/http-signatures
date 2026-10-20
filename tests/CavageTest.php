<?php

declare(strict_types=1);

namespace Femiwiki\HttpSignatures\Tests;

use Femiwiki\HttpSignatures\Cavage;
use Femiwiki\HttpSignatures\Digest;
use Femiwiki\HttpSignatures\Signature;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(Cavage::class)]
#[CoversClass(Digest::class)]
#[CoversClass(Signature::class)]
class CavageTest extends TestCase
{
    private const NOW = 1_792_320_000;

    /**
     * @return array{string, string} The private and the public key, in PEM
     */
    private static function newKeyPair(): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2_048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        $private = null;
        self::assertTrue(openssl_pkey_export($key, $private));
        self::assertIsString($private);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        $public = $details['key'] ?? null;
        self::assertIsString($public);
        return [$private, $public];
    }

    /**
     * @return array<string, string>
     */
    private static function newPost(string $body): array
    {
        return [
            'host' => 'fedi.example.org',
            'date' => gmdate('D, d M Y H:i:s \G\M\T', self::NOW),
            'digest' => Digest::of($body),
        ];
    }

    public function testSignedRequestVerifies(): void
    {
        [$private, $public] = self::newKeyPair();
        $headers = self::newPost('{}');
        $headers['signature'] = Cavage::sign(
            'POST',
            '/actors/inbox',
            $headers,
            'https://remote.example/users/a#main-key',
            $private,
        );

        $parsed = Signature::parse($headers['signature']);
        $this->assertNotNull($parsed);
        $this->assertSame('https://remote.example/users/a#main-key', $parsed->keyId);
        $this->assertSame(['(request-target)', 'host', 'date', 'digest'], $parsed->headers);
        $this->assertNull($parsed->check('POST', $headers, '{}', self::NOW));
        $this->assertTrue($parsed->verify('POST', '/actors/inbox', $headers, $public));

        $this->assertFalse($parsed->verify('POST', '/actors/category_1/inbox', $headers, $public));
        $this->assertFalse($parsed->verify('POST', '/actors/inbox', $headers, self::newKeyPair()[1]));
        unset($headers['digest']);
        $this->assertFalse($parsed->verify('POST', '/actors/inbox', $headers, $public));
    }

    public function testSignRefusesAKeyThatDoesNotLoad(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Cavage::sign('POST', '/', self::newPost('{}'), 'https://remote.example/users/a#main-key', 'not a key');
    }

    /**
     * @return iterable<string, array{string, string[], int, string, ?string}>
     */
    public static function provideCheck(): iterable
    {
        $signed = ['(request-target)', 'host', 'date', 'digest'];
        yield 'good' => ['rsa-sha256', $signed, 0, '{}', null];
        yield 'hs2019' => ['hs2019', $signed, 0, '{}', null];
        yield 'other algorithm' => ['hmac-sha256', $signed, 0, '{}', 'algorithm'];
        yield 'digest not signed' => ['rsa-sha256', ['(request-target)', 'host', 'date'], 0, '{}', 'headers'];
        yield 'an hour ahead and more' => ['rsa-sha256', $signed, -3_601, '{}', 'date'];
        yield 'twelve hours behind and more' => ['rsa-sha256', $signed, 43_201, '{}', 'date'];
        yield 'just inside' => ['rsa-sha256', $signed, 43_200, '{}', null];
        yield 'body changed' => ['rsa-sha256', $signed, 0, '{"a":1}', 'digest'];
    }

    /**
     * @param string[] $names
     */
    #[DataProvider('provideCheck')]
    public function testCheck(string $algorithm, array $names, int $age, string $body, ?string $expected): void
    {
        $parsed = new Signature('a', $algorithm, $names, 'a');
        $this->assertSame($expected, $parsed->check('POST', self::newPost('{}'), $body, self::NOW + $age));
    }

    public function testGetNeedsNoDigest(): void
    {
        $parsed = new Signature('a', null, ['(request-target)', 'host', 'date'], 'a');
        $headers = ['host' => 'fedi.example.org', 'date' => gmdate('D, d M Y H:i:s \G\M\T', self::NOW)];
        $this->assertNull($parsed->check('GET', $headers, '', self::NOW));
    }

    public function testParseRefusesWhatIsNotASignature(): void
    {
        $this->assertNull(Signature::parse(''));
        $this->assertNull(Signature::parse('keyId="a"'));
        $this->assertNull(Signature::parse('keyId="a",signature="not base64!"'));
        $this->assertSame(['date'], Signature::parse('keyId="a",signature="YQ=="')?->headers);
    }

    public function testSigningStringNeedsEveryNamedHeader(): void
    {
        $this->assertNull(Cavage::signingString('GET', '/', ['host' => 'a'], ['host', 'date']));
    }
}
