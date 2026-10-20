<?php

declare(strict_types=1);

namespace Femiwiki\HttpSignatures;

/**
 * draft-cavage-http-signatures-12 as Mastodon uses it: rsa-sha256 over (request-target), host,
 * date and, on a POST, digest.
 */
class Cavage
{
    public const ALGORITHM = 'rsa-sha256';

    /**
     * @param string $method
     * @param string $target The path and query the request was sent to
     * @param array<string,string> $headers Keyed by lower-case name
     * @param string[] $names The signed headers, in order
     * @return string|null Null when a named header is missing
     */
    public static function signingString(string $method, string $target, array $headers, array $names): ?string
    {
        $lines = [];
        foreach ($names as $name) {
            if ($name === '(request-target)') {
                $lines[] = '(request-target): ' . strtolower($method) . ' ' . $target;
                continue;
            }
            if (!array_key_exists($name, $headers)) {
                return null;
            }
            $lines[] = "{$name}: {$headers[$name]}";
        }
        return implode("\n", $lines);
    }

    /**
     * The Signature header for a request, signing (request-target) and every header given.
     *
     * @param string $method
     * @param string $target
     * @param array<string,string> $headers Keyed by lower-case name
     * @param string $keyId
     * @param string $privateKeyPem
     * @return string
     * @throws \InvalidArgumentException When the private key does not load
     */
    public static function sign(
        string $method,
        string $target,
        array $headers,
        string $keyId,
        string $privateKeyPem,
    ): string {
        $key = openssl_pkey_get_private($privateKeyPem);
        if ($key === false) {
            throw new \InvalidArgumentException('The private key does not load');
        }
        $names = array_merge(['(request-target)'], array_keys($headers));
        $signature = '';
        $signed = openssl_sign(
            (string) self::signingString($method, $target, $headers, $names),
            $signature,
            $key,
            OPENSSL_ALGO_SHA256,
        );
        if (!$signed) {
            throw new \InvalidArgumentException('The private key cannot sign');
        }
        return sprintf(
            'keyId="%s",algorithm="%s",headers="%s",signature="%s"',
            $keyId,
            self::ALGORITHM,
            implode(' ', $names),
            base64_encode($signature),
        );
    }

    public static function verify(string $signingString, string $signature, string $publicKeyPem): bool
    {
        return openssl_verify($signingString, $signature, $publicKeyPem, OPENSSL_ALGO_SHA256) === 1;
    }
}
