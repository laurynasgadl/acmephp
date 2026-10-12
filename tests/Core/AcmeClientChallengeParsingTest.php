<?php

declare(strict_types=1);

namespace Tests\AcmePhp\Core;

use AcmePhp\Core\AcmeClient;
use AcmePhp\Core\Http\Base64SafeEncoder;
use AcmePhp\Core\Http\SecureHttpClient;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use AcmePhp\Core\Protocol\CertificateOrder;
use LogicException;
use PHPUnit\Framework\TestCase;

class AcmeClientChallengeParsingTest extends TestCase
{
    private const string DIRECTORY_URL = 'https://acme.test/directory';
    private const string ORDER_URL = 'https://acme.test/order/1';
    private const string AUTHZ_URL = 'https://acme.test/authz/1';

    public function testRequestOrderSkipsChallengesWithoutToken(): void
    {
        $client = new AcmeClient($this->createHttpClient(), self::DIRECTORY_URL);

        $this->assertHttpAndDnsChallengesOnly($client->requestOrder(['example.com']));
    }

    public function testReloadOrderSkipsChallengesWithoutToken(): void
    {
        $client = new AcmeClient($this->createHttpClient(), self::DIRECTORY_URL);

        $this->assertHttpAndDnsChallengesOnly($client->reloadOrder(new CertificateOrder([], self::ORDER_URL)));
    }

    private function assertHttpAndDnsChallengesOnly(CertificateOrder $order): void
    {
        $challenges = $order->getAuthorizationChallenges('example.com');

        $this->assertCount(2, $challenges);
        $this->assertSame(
            ['http-01', 'dns-01'],
            array_map(static fn (AuthorizationChallenge $challenge) => $challenge->getType(), $challenges)
        );
        $this->assertSame('http-token', $challenges[0]->getToken());
        $this->assertSame('http-token.dGh1bWJwcmludA', $challenges[0]->getPayload());
    }

    private function createHttpClient(): SecureHttpClient
    {
        $httpClient = $this->createMock(SecureHttpClient::class);
        $httpClient->method('getBase64Encoder')->willReturn(new Base64SafeEncoder());
        $httpClient->method('getJWKThumbprint')->willReturn('thumbprint');
        $httpClient->method('signKidPayload')->willReturn([]);
        $httpClient->method('signJwkPayload')->willReturn([]);
        $httpClient->method('getLastLocation')->willReturnOnConsecutiveCalls('https://acme.test/account/1', self::ORDER_URL);
        $httpClient->method('request')->willReturnCallback(static function (string $method, string $endpoint) {
            switch ($endpoint) {
                case self::DIRECTORY_URL:
                    return [
                        'newAccount' => 'https://acme.test/new-account',
                        'newOrder' => 'https://acme.test/new-order',
                        'newNonce' => 'https://acme.test/new-nonce',
                        'revokeCert' => 'https://acme.test/revoke-cert',
                    ];
                case 'https://acme.test/new-account':
                    return [];
                case 'https://acme.test/new-order':
                case self::ORDER_URL:
                    return ['status' => 'pending', 'authorizations' => [self::AUTHZ_URL]];
                case self::AUTHZ_URL:
                    return [
                        'identifier' => ['type' => 'dns', 'value' => 'example.com'],
                        'status' => 'pending',
                        'challenges' => [
                            ['type' => 'http-01', 'url' => 'https://acme.test/chall/1', 'status' => 'pending', 'token' => 'http-token'],
                            ['type' => 'dns-persist-01', 'url' => 'https://acme.test/chall/2', 'status' => 'pending', 'issuer-domain-names' => ['acme.test']],
                            ['type' => 'dns-01', 'url' => 'https://acme.test/chall/3', 'status' => 'pending', 'token' => 'dns-token'],
                        ],
                    ];
            }

            throw new LogicException('Unexpected request to '.$endpoint);
        });

        return $httpClient;
    }
}
