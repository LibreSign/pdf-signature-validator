<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Model\TimestampToken;
use LibreSign\PdfSignatureValidator\Parser\CmsTimestampExtractor;
use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Element;
use PHPUnit\Framework\TestCase;

final class CmsTimestampExtractorTest extends TestCase
{
    public function testExtractsTimestampTokenMetadataFromCms(): void
    {
        $timestamp = (new CmsTimestampExtractor())->extract($this->createCmsWithTimestampToken());

        self::assertInstanceOf(TimestampToken::class, $timestamp);
        self::assertSame('2026-09-03T20:00:00+00:00', $timestamp->generatedAt?->format(DATE_ATOM));
        self::assertSame('1.2.3.4.1', $timestamp->policyOid);
        self::assertSame('4097', $timestamp->serialNumber);
        self::assertSame('Example TSA', $timestamp->certificateSubject['commonName'] ?? null);
    }

    public function testReturnsNullWhenCmsHasNoTimestampToken(): void
    {
        self::assertNull((new CmsTimestampExtractor())->extract("\x30\x00"));
    }

    private function createCmsWithTimestampToken(): string
    {
        $tstInfo = ASN1::encodeDER([
            'version' => 1,
            'policy' => '1.2.3.4.1',
            'messageImprint' => [
                'hashAlgorithm' => ['algorithm' => '2.16.840.1.101.3.4.2.1'],
                'hashedMessage' => str_repeat("\x00", 32),
            ],
            'serialNumber' => 4097,
            'genTime' => '2026-09-03 20:00:00',
        ], $this->tstInfoMap());

        $timestampContent = ASN1::encodeDER([
            'contentType' => '1.2.840.113549.1.9.16.1.4',
            'content' => $tstInfo,
            'certificateSubject' => [
                'oid' => '2.5.4.3',
                'value' => 'Example TSA',
            ],
        ], [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'contentType' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
                'content' => ['type' => ASN1::TYPE_OCTET_STRING],
                'certificateSubject' => [
                    'type' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        'oid' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
                        'value' => ['type' => ASN1::TYPE_UTF8_STRING],
                    ],
                ],
            ],
        ]);

        return ASN1::encodeDER([
            'type' => '1.2.840.113549.1.9.16.2.14',
            'values' => [new Element($timestampContent)],
        ], [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'type' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
                'values' => [
                    'type' => ASN1::TYPE_SET,
                    'min' => 1,
                    'max' => -1,
                    'children' => ['type' => ASN1::TYPE_ANY],
                ],
            ],
        ]);
    }

    private function tstInfoMap(): array
    {
        return [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'version' => ['type' => ASN1::TYPE_INTEGER],
                'policy' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
                'messageImprint' => [
                    'type' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        'hashAlgorithm' => [
                            'type' => ASN1::TYPE_SEQUENCE,
                            'children' => [
                                'algorithm' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
                            ],
                        ],
                        'hashedMessage' => ['type' => ASN1::TYPE_OCTET_STRING],
                    ],
                ],
                'serialNumber' => ['type' => ASN1::TYPE_INTEGER],
                'genTime' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
            ],
        ];
    }
}
