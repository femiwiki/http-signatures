<?php

declare(strict_types=1);

namespace Femiwiki\HttpSignatures;

/**
 * The Digest header (RFC 3230) that draft-cavage signatures cover on a POST, with SHA-256 only.
 */
class Digest
{
    /**
     * The Digest header for a body.
     */
    public static function of(string $body): string
    {
        return 'SHA-256=' . base64_encode(hash('sha256', $body, binary: true));
    }

    /**
     * Whether a Digest header, which may list several digests, has the SHA-256 one of the body.
     */
    public static function matches(string $header, string $body): bool
    {
        $expected = self::of($body);
        foreach (explode(',', $header) as $digest) {
            $parts = explode('=', trim($digest), limit: 2);
            if (count($parts) === 2 && strtoupper($parts[0]) . '=' . $parts[1] === $expected) {
                return true;
            }
        }
        return false;
    }
}
