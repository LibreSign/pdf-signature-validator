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
        $signedRevision = 'ABC%%EOF';
        $content = $signedRevision . 'X';

        $result = $this->analyze(
            [$this->signatureEndingAt(strlen($signedRevision), 2)],
            $content,
        );

        $this->assertSame(
            DocumentModificationState::TRAILING_DATA,
            $result[0]->metadata->documentModificationState,
        );
    }

    public function testTreatsOptionalEolAfterSignedRevisionAsUnchanged(): void
    {
        $signedRevision = 'ABC%%EOF';
        $content = $signedRevision . "\r\n";

        $result = $this->analyze(
            [$this->signatureEndingAt(strlen($signedRevision), 2)],
            $content,
        );

        $this->assertSame(
            DocumentModificationState::UNCHANGED,
            $result[0]->metadata->documentModificationState,
        );
    }

    public function testRejectsNonEolWhitespaceAfterFinalEof(): void
    {
        $signedRevision = 'ABC%%EOF';
        $content = $signedRevision . "\x20";

        $result = $this->analyze(
            [$this->signatureEndingAt(strlen($signedRevision), 2)],
            $content,
        );

        $this->assertSame(
            DocumentModificationState::TRAILING_DATA,
            $result[0]->metadata->documentModificationState,
        );
    }

    public function testReportsInvalidRevisionBoundary(): void
    {
        $content = 'ABCDEFG';

        $result = $this->analyze(
            [$this->signatureEndingAt(strlen($content), 2)],
            $content,
        );

        $this->assertSame(
            DocumentModificationState::INVALID_REVISION_BOUNDARY,
            $result[0]->metadata->documentModificationState,
        );
    }

    public function testDetectsUnsignedContentAfterLastSignature(): void
    {
        $signedRevision = 'ABC%%EOF';
        $content = $signedRevision
            . "\n2 0 obj\n<< /Type /Catalog >>\nendobj\n"
            . "startxref\n20\n%%EOF\n";

        $result = $this->analyze(
            [$this->signatureEndingAt(strlen($signedRevision), 2)],
            $content,
        );

        $this->assertSame(
            DocumentModificationState::UNSIGNED_CONTENT,
            $result[0]->metadata->documentModificationState,
        );
    }

    public function testUsesContentsOffsetToIdentifyLastSignature(): void
    {
        $content = str_repeat('X', 200);

        $result = $this->analyze(
            [
                $this->signature($this->range(10, 20, 80), 15),
                $this->signature($this->range(100, 110, 180), 105),
            ],
            $content,
        );

        $this->assertNull($result[0]->metadata->documentModificationState);
        $this->assertNotNull($result[1]->metadata->documentModificationState);
    }

    public function testInvalidOlderByteRangeDoesNotOverrideLatestSignature(): void
    {
        $content = str_repeat('X', 200);

        $result = $this->analyze(
            [
                $this->signature($this->range(10, 20, 999999), 15),
                $this->signature($this->range(100, 110, 180), 105),
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
        $content = str_repeat('X', 200);

        $result = $this->analyze(
            [
                $this->signature($this->range(10, 20, 80), 15),
                $this->signature($this->range(100, 110, 999999), 105),
            ],
            $content,
        );

        $this->assertNull($result[0]->metadata->documentModificationState);
        $this->assertSame(
            DocumentModificationState::INVALID_BYTE_RANGE,
            $result[1]->metadata->documentModificationState,
        );
    }

    public function testFallsBackToFirstRangeEndWhenContentsOffsetIsUnavailable(): void
    {
        $content = str_repeat('X', 200);

        $result = $this->analyze(
            [
                $this->signature($this->range(10, 20, 190), null),
                $this->signature($this->range(100, 110, 150), null),
            ],
            $content,
        );

        $this->assertNull($result[0]->metadata->documentModificationState);
        $this->assertNotNull($result[1]->metadata->documentModificationState);
    }

    /**
     * @param list<ExtractedSignature> $signatures
     * @return list<ExtractedSignature>
     */
    private function analyze(array $signatures, string $content): array
    {
        return (new PdfDocumentModificationAnalyzer())
            ->enrichLastSignatureMetadata($signatures, $content);
    }

    private function signatureEndingAt(
        int $signedEnd,
        ?int $contentsOffset,
    ): ExtractedSignature {
        return $this->signature(
            [
                'offset1' => 0,
                'length1' => 1,
                'offset2' => 3,
                'length2' => $signedEnd,
            ],
            $contentsOffset,
        );
    }

    /**
     * @return array{offset1:int,length1:int,offset2:int,length2:int}
     */
    private function range(
        int $length1,
        int $offset2,
        int $signedEnd,
    ): array {
        return [
            'offset1' => 0,
            'length1' => $length1,
            'offset2' => $offset2,
            'length2' => $signedEnd,
        ];
    }

    /**
     * @param array{offset1:int,length1:int,offset2:int,length2:int} $range
     */
    private function signature(
        array $range,
        ?int $contentsOffset,
    ): ExtractedSignature {
        return new ExtractedSignature(
            'signature',
            new SignatureMetadata(
                null,
                $range,
                'adbe.pkcs7.detached',
                false,
                $contentsOffset,
            ),
            null,
        );
    }
}
