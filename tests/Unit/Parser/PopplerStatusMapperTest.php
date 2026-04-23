<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Parser\PopplerStatusMapper;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PopplerStatusMapperTest extends TestCase
{
    #[DataProvider('signatureStatusProvider')]
    public function testSignatureStatusMappingMatchesLegacyRules(string $raw, int $expectedId, string $expectedLabel): void
    {
        $mapper = new PopplerStatusMapper();
        $status = $mapper->mapSignatureStatus($raw);
        $this->assertSame($expectedId, $status->id);
        $this->assertSame($expectedLabel, $status->label);
        $this->assertSame($raw, $status->raw);
    }

    #[DataProvider('certificateStatusProvider')]
    public function testCertificateStatusMappingMatchesLegacyRules(string $raw, int $expectedId, string $expectedLabel): void
    {
        $mapper = new PopplerStatusMapper();
        $status = $mapper->mapCertificateStatus($raw);
        $this->assertSame($expectedId, $status->id);
        $this->assertSame($expectedLabel, $status->label);
        $this->assertSame($raw, $status->raw);
    }

    /**
     * @return iterable<string, array{0:string,1:int,2:string}>
     */
    public static function signatureStatusProvider(): iterable
    {
        yield 'valid' => ['Signature is Valid.', 1, 'Signature is valid.'];
        yield 'invalid' => ['Signature is Invalid.', 2, 'Signature is invalid.'];
        yield 'digest_mismatch' => ['Digest Mismatch.', 3, 'Digest mismatch.'];
        yield 'unsigned' => ["Document isn't signed or corrupted data.", 4, "Document isn't signed or corrupted data."];
        yield 'not_verified' => ['Signature has not yet been verified.', 5, 'Signature has not yet been verified.'];
        yield 'unknown' => ['Unknown legacy status', 6, 'Unknown validation failure.'];
    }

    /**
     * @return iterable<string, array{0:string,1:int,2:string}>
     */
    public static function certificateStatusProvider(): iterable
    {
        yield 'trusted' => ['Certificate is Trusted.', 1, 'Certificate is trusted.'];
        yield 'issuer_not_trusted' => ["Certificate issuer isn't Trusted.", 2, "Certificate issuer isn't trusted."];
        yield 'issuer_unknown' => ['Certificate issuer is unknown.', 3, 'Certificate issuer is unknown.'];
        yield 'revoked' => ['Certificate has been Revoked.', 4, 'Certificate has been revoked.'];
        yield 'expired' => ['Certificate has Expired', 5, 'Certificate has expired'];
        yield 'not_verified' => ['Certificate has not yet been verified.', 6, 'Certificate has not yet been verified.'];
        yield 'unknown' => ['Unknown legacy status', 7, 'Unknown issue with Certificate or corrupted data.'];
    }
}
