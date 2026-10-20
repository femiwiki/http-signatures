# http-signatures

Sign and verify HTTP signatures as ActivityPub servers use them, in PHP with
nothing but the `openssl` extension.

So far it covers [draft-cavage-http-signatures-12] the way Mastodon uses it:
`rsa-sha256` over `(request-target)`, `host`, `date` and, on a POST, `digest`.
[RFC 9421] will come as its own class beside it.

The library does no I/O. Fetching the sender's public key, caching it and
telling the time are left to the caller, so it fits any framework.

```php
use Femiwiki\HttpSignatures\Cavage;
use Femiwiki\HttpSignatures\Digest;
use Femiwiki\HttpSignatures\Signature;

// Sending
$headers = [
    'host' => 'remote.example',
    'date' => gmdate('D, d M Y H:i:s \G\M\T'),
    'digest' => Digest::of($body),
];
$headers['signature'] = Cavage::sign('POST', '/inbox', $headers, $keyId, $privateKeyPem);

// Receiving, with headers keyed by lower-case name
$signature = Signature::parse($headers['signature']);
if ($signature && $signature->check('POST', $headers, $body, time()) === null) {
    $good = $signature->verify('POST', $target, $headers, $publicKeyPemOf($signature->keyId));
}
```

It was split out of [FediFeeds](https://github.com/femiwiki/FediFeeds), which
keeps its MediaWiki adapters.

Licensed under the [Apache License 2.0](LICENSE).

[draft-cavage-http-signatures-12]: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12
[RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421
