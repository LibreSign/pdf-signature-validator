<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Model\DocumentModificationState;
use LibreSign\PdfSignatureValidator\Model\ExtractedSignature;
use LibreSign\PdfSignatureValidator\Model\SignatureMetadata;
use LibreSign\PdfSignatureValidator\Parser\PdfDocumentModificationAnalyzer;
use PHPUnit\Framework\TestCase;

final class PdfDocumentModificationAnalyzerTest extends TestCase
{
    public function testDetectsTrailingDataAfterFinalEof(): void
    {
        $analyzer = new PdfDocumentModificationAnalyzer();
        $content = 'ABCD%%EOFX';

        $result = $analyzer->enrichLastSignatureMetadata(
            [$this->signature([0, 2, 2, 2], 1)],
            $content,
        );

        $this->assertSame(
            DocumentModificationState::TRAILING_DATA,
            $result[0]->metadata->documentModificationState,
        );
    }

    public function testTreatsPdfWhitespaceAfterSignatureAsUnchanged(): void
    {
        $analyzer = new PdfDocumentModificationAnalyzer();
        $content = "ABCD\x00\x09\x0A\x0C\x0D\x20";

        $result = $analyzer->enrichLastSignatureMetadata(
            [$this->signature([0, 2, 2, 2], 1)],
            $content,
        );

        $this->assertSame(
            DocumentModificationState::UNCHANGED,
            $result[0]->metadata->documentModificationState,
        );
    }

    public function testDetectsVerticalTabAsUnsignedContent(): void
    {
        $analyzer = new PdfDocumentModificationAnalyzer();
        $content = "ABCD\x0B";

        $result = $analyzer->enrichLastSignatureMetadata(
            [$this->signature([0, 2, 2, 2], 1)],
            $content,
        );

        $this->assertSame(
            DocumentModificationState::UNSIGNED_CONTENT,
            $result[0]->metadata->documentModificationState,
        );
    }

    public function testDetectsUnsignedContentAfterLastSignature(): void
    {
        $analyzer = new PdfDocumentModificationAnalyzer();
        $content = "ABCD\n2 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF";

        $result = $analyzer->enrichLastSignatureMetadata(
            [$this->signature([0, 2, 2, 2], 1)],
            $content,
        );

        $this->assertSame(
            DocumentModificationState::UNSIGNED_CONTENT,
            $result[0]->metadata->documentModificationState,
        );
    }

    public function testUsesContentsOffsetToIdentifyLastSignature(): void
    {
        $analyzer = new PdfDocumentModificationAnalyzer();
        $content = str_repeat('X', 200);

        $result = $analyzer->enrichLastSignatureMetadata(
            [
                $this->signature([0, 10, 20, 80], 10),
                $this->signature([0, 10, 20, 180], 100),
            ],
            $content,
        );

        $this->assertNull($result[0]->metadata->documentModificationState);
        $this->assertNotNull($result[1]->metadata->documentModificationState);
    }

    public function testInvalidByteRangeOnOlderSignatureDoesNotOverrideLatestSignature(): void
    {
        $analyzer = new PdfDocumentModificationAnalyzer();
        $content = str_repeat('X', 200);

        $result = $analyzer->enrichLastSignatureMetadata(
            [
                $this->signature([0, 10, 20, 999999], 10),
                $this->signature([0, 10, 20, 180], 100),
            ],
            $content,
        );

        $this->assertNull($result[0]->metadata->documentModificationState);
        $this->assertNotSame(
            DocumentModificationState::INVALID_BYTE_RANGE,
            $result[1]->metadata->documentModificationState,
        );
    }

    public function testLatestSignatureReportsInvalidByteRange(): void
    {
        $analyzer = new PdfDocumentModificationAnalyzer();
        $content = str_repeat('X', 200);

        $result = $analyzer->enrichLastSignatureMetadata(
            [
                $this->signature([0, 10, 20, 80], 10),
                $this->signature([0, 10, 20, 999999], 100),
            ],
            $content,
        );

        $this->assertNull($result[0]->metadata->documentModificationState);
        $this->assertSame(
            DocumentModificationState::INVALID_BYTE_RANGE,
            $result[1]->metadata->documentModificationState,
        );
    }

    public function testFallsBackToByteRangeWhenContentsOffsetIsUnavailable(): void
    {
        $analyzer = new PdfDocumentModificationAnalyzer();
        $content = str_repeat('X', 200);

        $result = $analyzer->enrichLastSignatureMetadata(
            [
                $this->signature([0, 10, 20, 80], null),
                $this->signature([0, 10, 20, 180], null),
            ],
            $content,
        );

        $this->assertNull($result[0]->metadata->documentModificationState);
        $this->assertNotNull($result[1]->metadata->documentModificationState);
    }

    /**
     * @param array{0:int,1:int,2:int,3:int} $range
     */
    private function signature(array $range, ?int $contentsOffset): ExtractedSignature
    {
        [$offset1, $length1, $offset2, $length2] = $range;

        return new ExtractedSignature(
            'signature',
            new SignatureMetadata(
                null,
                [
                    'offset1' => $offset1,
                    'length1' => $length1,
                    'offset2' => $offset2,
                    'length2' => $offset2 + $length2,
                ],
                'adbe.pkcs7.detached',
                false,
                $contentsOffset,
            ),
            null,
        );
    }
}
