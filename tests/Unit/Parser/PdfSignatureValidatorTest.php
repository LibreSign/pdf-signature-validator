<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Exception\UnsignedPdfException;
use LibreSign\PdfSignatureValidator\Model\TimestampToken;
use LibreSign\PdfSignatureValidator\Model\ValidationState;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for complete PDF signature validation.
 */
final class PdfSignatureValidatorTest extends TestCase
{
    private PdfSignatureValidator $validator;

    protected function setUp(): void
    {
        $this->validator = new PdfSignatureValidator();
    }

    public function testValidateUnsignedPdf(): void
    {
        $unsignedPdf = '%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
190
%%EOF';

        $this->expectException(UnsignedPdfException::class);
        $this->validator->validateFromString($unsignedPdf);
    }

    public function testValidateFromResourceWithValidResource(): void
    {
        $pdf = '%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
190
%%EOF';

        $resource = fopen('php://memory', 'r+');
        fwrite($resource, $pdf);
        rewind($resource);

        $this->expectException(UnsignedPdfException::class);
        $this->validator->validateFromResource($resource);

        fclose($resource);
    }

    #[DataProvider('signedPdfIntegrityProvider')]
    public function testClassifiesSignedPdfIntegrity(
        string $fixture,
        string $change,
        ValidationState $expectedSignatureState,
        bool $coversEntireDocument,
        bool $expectsTimestamp,
    ): void {
        $content = $this->signedPdfContent($fixture);
        if ($change === 'signed-byte-modified') {
            $content[10] = $content[10] === 'x' ? 'y' : 'x';
        } elseif ($change === 'trailing-bytes') {
            $content .= "\nextra bytes";
        }

        $result = $this->validator->validateFromString($content);

        $this->assertSame($expectedSignatureState, $result[0]['signatureValidation']->state);
        $this->assertFalse($result[0]['certificateValidation']->isValid);
        $this->assertSame($coversEntireDocument, $result[0]['signature']->metadata->coversEntireDocument);
        $this->assertArrayHasKey('timestamp', $result[0]);
        if ($expectsTimestamp) {
            $this->assertInstanceOf(TimestampToken::class, $result[0]['timestamp']);
            $this->assertSame('1.2.3.4.1', $result[0]['timestamp']->policyOid);
            $this->assertNotNull($result[0]['timestamp']->serialNumber);
            $this->assertSame('www.freetsa.org', $result[0]['timestamp']->certificateSubject['commonName'] ?? null);
        } else {
            $this->assertNull($result[0]['timestamp']);
        }
    }

    public function testConstructorWithTrustedRoots(): void
    {
        $cert1 = 'CERT1';
        $cert2 = 'CERT2';

        $validator = new PdfSignatureValidator(
            trustedRoots: [$cert1, $cert2]
        );

        $roots = $validator->getTrustedRoots();
        $this->assertCount(2, $roots);
        $this->assertContains($cert1, $roots);
        $this->assertContains($cert2, $roots);
    }

    public function testSetTrustedRoots(): void
    {
        $cert1 = 'CA_LIBRESIGN_ROOT';
        $cert2 = 'CA_THIRD_PARTY';

        $this->validator->setTrustedRoots([$cert1, $cert2]);

        $roots = $this->validator->getTrustedRoots();
        $this->assertCount(2, $roots);
        $this->assertSame([$cert1, $cert2], $roots);
    }

    public function testAddTrustedRoot(): void
    {
        $libresignCa = 'CA_LIBRESIGN_CERTIFICATE';

        $this->validator->addTrustedRoot($libresignCa);

        $roots = $this->validator->getTrustedRoots();
        $this->assertCount(1, $roots);
        $this->assertContains($libresignCa, $roots);

        // Add another root
        $thirdPartyCa = 'CA_THIRD_PARTY';
        $this->validator->addTrustedRoot($thirdPartyCa);

        $roots = $this->validator->getTrustedRoots();
        $this->assertCount(2, $roots);
        $this->assertContains($libresignCa, $roots);
        $this->assertContains($thirdPartyCa, $roots);
    }

    public function testAddDuplicateTrustedRootIsNotAdded(): void
    {
        $cert = 'CERTIFICATE_X';

        $this->validator->addTrustedRoot($cert);
        $this->validator->addTrustedRoot($cert); // Add same again

        $roots = $this->validator->getTrustedRoots();
        // Should still be just 1, not 2
        $this->assertCount(1, $roots);
    }

    /**
    * @return iterable<string, array{0: string, 1: string, 2: ValidationState, 3: bool, 4: bool}>
     */
    public static function signedPdfIntegrityProvider(): iterable
    {
        foreach (['small_valid-signed.pdf', 'real_jsignpdf_level1.pdf'] as $fixture) {
            $expectsTimestamp = $fixture === 'real_jsignpdf_level1.pdf';
            yield $fixture . ' is intact' => [
                $fixture,
                'intact',
                ValidationState::SIGNATURE_VALID,
                true,
                $expectsTimestamp,
            ];
            yield $fixture . ' has a modified signed byte' => [
                $fixture,
                'signed-byte-modified',
                ValidationState::SIGNATURE_INVALID,
                true,
                $expectsTimestamp,
            ];
            yield $fixture . ' has trailing bytes' => [
                $fixture,
                'trailing-bytes',
                ValidationState::SIGNATURE_VALID,
                false,
                $expectsTimestamp,
            ];
        }
    }

    private function signedPdfContent(string $fixture): string
    {
        $content = file_get_contents(__DIR__ . '/../../Fixtures/pdfs/' . $fixture);
        $this->assertIsString($content);

        return $content;
    }
}
