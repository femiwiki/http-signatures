<?php

declare(strict_types=1);

namespace Femiwiki\HttpSignatures;

/**
 * A received draft-cavage Signature header.
 */
final readonly class Signature
{
    /** Mastodon's CLOCK_SKEW_MARGIN and EXPIRATION_WINDOW_LIMIT, in seconds */
    public const MAX_AHEAD = 3_600;
    public const MAX_BEHIND = 43_200;

    /**
     * @param string[] $headers The signed headers, in order
     */
    public function __construct(
        public string $keyId,
        public ?string $algorithm,
        public array $headers,
        public string $signature,
    ) {}

    /**
     * @param string $header The Signature header
     * @return self|null Null when it names no key or carries no signature
     */
    public static function parse(string $header): ?self
    {
        $matches = [];
        preg_match_all('/(\w+)="([^"]*)"/', $header, $matches, PREG_SET_ORDER);
        $fields = array_column($matches, 2, 1);
        $signature = base64_decode($fields['signature'] ?? '', strict: true);
        if (!array_key_exists('keyId', $fields) || !$signature) {
            return null;
        }
        return new self(
            $fields['keyId'],
            $fields['algorithm'] ?? null,
            explode(' ', strtolower($fields['headers'] ?? 'date')),
            $signature,
        );
    }

    /**
     * Why this signature cannot be good whatever the key, or null if it can be.
     *
     * @param array<string,string> $headers Keyed by lower-case name
     * @param int $now Unix time
     */
    public function check(string $method, array $headers, string $body, int $now): ?string
    {
        if (!in_array($this->algorithm, [null, Cavage::ALGORITHM, 'hs2019'], strict: true)) {
            return 'algorithm';
        }
        $post = strtoupper($method) === 'POST';
        $required = $post ? ['(request-target)', 'host', 'date', 'digest'] : ['(request-target)', 'host', 'date'];
        if (array_diff($required, $this->headers)) {
            return 'headers';
        }
        // A date that does not parse reads as 1970, far behind
        $age = $now - (int) strtotime($headers['date'] ?? '');
        if ($age < -self::MAX_AHEAD || $age > self::MAX_BEHIND) {
            return 'date';
        }
        if ($post && !Digest::matches($headers['digest'] ?? '', $body)) {
            return 'digest';
        }
        return null;
    }

    /**
     * Whether the public key signed this over the request.
     *
     * @param array<string,string> $headers Keyed by lower-case name
     */
    public function verify(string $method, string $target, array $headers, string $publicKeyPem): bool
    {
        $string = Cavage::signingString($method, $target, $headers, $this->headers);
        return $string !== null && Cavage::verify($string, $this->signature, $publicKeyPem);
    }
}
