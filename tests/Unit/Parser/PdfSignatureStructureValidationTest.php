<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\\PdfSignatureValidator\\Tests\\Unit\\Parser;

use LibreSign\\PdfSignatureValidator\\Model\\ValidationReason;
use LibreSign\\PdfSignatureValidator\\Model\\ValidationState;
use LibreSign\\PdfSignatureValidator\\Parser\\PdfSignatureValidator;
use PHPUnit\\Framework\\TestCase;

final class PdfSignatureStructureValidationTest extends TestCase
{
    private PdfSignatureValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new PdfSignatureValidator();
    }

    public function testRejectsStructurallyInvalidByteRangeBeforeCmsValidation(): void
    {
        $content = $this->signedPdfContent();

        $content = preg_replace(
            '/\\/ByteRange\\s*\\[\\s*0\\b/',
            '/ByteRange [1',
            $content,
            1,
            $count,
        );

        $this->assertSame(1, $count);
        $this->assertIsString($content);

        $result = $this->validator->validateFromString($content);

        $this->assertSame(
            ValidationState::NOT_VERIFIED,
            $result[0]['signatureValidation']->state,
        );
        $this->assertSame(
            ValidationReason::INVALID_BYTE_RANGE,
            $result[0]['signatureValidation']->reasonCode,
        );
    }

    public function testRejectsSignedRevisionWithoutValidEofBoundary(): void
    {
        $content = $this->signedPdfContent();

        $this->assertSame(
            1,
            preg_match(
                '/\\/ByteRange\\s*\\[\\s*\\d+\\s+\\d+\\s+(\\d+)\\s+(\\d+)\\s*\\]/',
                $content,
                $matches,
            ),
        );

        $signedEnd = (int)$matches[1] + (int)$matches[2];
        $signedRevision = substr($content, 0, $signedEnd);
        $eofOffset = strrpos($signedRevision, '%%EOF');

        $this->assertNotFalse($eofOffset);

        $content[$eofOffset + 2] = 'X';

        $result = $this->validator->validateFromString($content);

        $this->assertSame(
            ValidationState::NOT_VERIFIED,
            $result[0]['signatureValidation']->state,
        );
        $this->assertSame(
            ValidationReason::INVALID_EOF_BOUNDARY,
            $result[0]['signatureValidation']->reasonCode,
        );
    }

    public function testDoesNotValidateRfc3161AsDetachedCms(): void
    {
        $content = $this->replaceSubFilter(
            $this->signedPdfContent(),
            'ETSI.RFC3161',
        );

        $this->assertUnsupportedSubFilter($content);
    }

    public function testDoesNotValidatePkcs7Sha1AsDetachedCms(): void
    {
        $content = $this->replaceSubFilter(
            $this->signedPdfContent(),
            'adbe.pkcs7.sha1',
        );

        $this->assertUnsupportedSubFilter($content);
    }

    public function testDoesNotAssumeDetachedCmsWhenSubFilterIsMissing(): void
    {
        $content = $this->signedPdfContent();

        $content = preg_replace(
            '/\\/SubFilter\\s*\\/[A-Za-z0-9.\\-_]+/',
            '',
            $content,
            1,
            $count,
        );

        $this->assertSame(1, $count);
        $this->assertIsString($content);

        $this->assertUnsupportedSubFilter($content);
    }

    public function testStructuralFailureTakesPrecedenceOverUnsupportedSubFilter(): void
    {
        $content = $this->replaceSubFilter(
            $this->signedPdfContent(),
            'ETSI.RFC3161',
        );

        $content = preg_replace(
            '/\\/ByteRange\\s*\\[\\s*0\\b/',
            '/ByteRange [1',
            $content,
            1,
            $count,
        );

        $this->assertSame(1, $count);
        $this->assertIsString($content);

        $result = $this->validator->validateFromString($content);

        $this->assertSame(
            ValidationReason::INVALID_BYTE_RANGE,
            $result[0]['signatureValidation']->reasonCode,
        );
    }

    private function assertUnsupportedSubFilter(string $content): void
    {
        $result = $this->validator->validateFromString($content);

        $this->assertSame(
            ValidationState::NOT_VERIFIED,
            $result[0]['signatureValidation']->state,
        );
        $this->assertSame(
            ValidationReason::UNSUPPORTED_SUBFILTER,
            $result[0]['signatureValidation']->reasonCode,
        );
    }

    private function replaceSubFilter(
        string $content,
        string $subFilter,
    ): string {
        $updated = preg_replace(
            '/\\/SubFilter\\s*\\/[A-Za-z0-9.\\-_]+/',
            '/SubFilter /' . $subFilter,
            $content,
            1,
            $count,
        );

        $this->assertSame(1, $count);
        $this->assertIsString($updated);

        return $updated;
    }

    private function signedPdfContent(): string
    {
        $content = file_get_contents(
            __DIR__ . '/../../Fixtures/pdfs/small_valid-signed.pdf',
        );

        $this->assertIsString($content);

        return $content;
    }
}
