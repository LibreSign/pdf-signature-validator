<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Validation\DocMdp;

use LibreSign\PdfSignatureValidator\Parser\PdfSignatureExtractor;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\DocMdpValidationDataInspector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Real signed PDFs produced with pyHanko 0.38.2 from the project's own blank
 * PDF fixture, then independently classified by pyHanko's diff policy.
 *
 * These are structural DocMDP expectations; certificate trust is orthogonal.
 */
final class DocMdpCorpusTest extends TestCase
{
    /**
     * @return iterable<string,array{string,bool}>
     */
    public static function certifiedPdfCases(): iterable
    {
        yield 'P1 certified without updates' => ['pyhanko-p1-certified.pdf', false];
        yield 'P1 with genuine DSS' => ['pyhanko-p1-dss.pdf', true];
        yield 'P1 DSS introducing an Info dictionary' => ['pyhanko-p1-noinfo-dss.pdf', true];
        yield 'P1 with genuine VRI and DSS' => ['pyhanko-p1-dss-vri.pdf', true];
        yield 'P1 with document timestamp' => ['pyhanko-p1-timestamp.pdf', true];
        yield 'P1 with unauthorized catalog action' => ['pyhanko-p1-action.pdf', false];
        yield 'P1 with DSS and unauthorized action' => ['pyhanko-p1-dss-action.pdf', false];
        yield 'P1 with DSS and invalid VRI value' => ['pyhanko-p1-dss-invalid-vri-null.pdf', false];
        yield 'P1 with DSS and invalid VRI entry' => ['pyhanko-p1-dss-invalid-vri-dict.pdf', false];
        yield 'P2 with genuine DSS' => ['pyhanko-p2-dss.pdf', true];
        yield 'P3 with genuine DSS' => ['pyhanko-p3-dss.pdf', true];
    }

    #[DataProvider('certifiedPdfCases')]
    public function testOnlyAllowsDocumentValidationUpdates(string $file, bool $expected): void
    {
        $path = __DIR__ . '/../../../Fixtures/docmdp/' . $file;
        $content = file_get_contents($path);
        self::assertIsString($content, $file);

        $signatures = (new PdfSignatureExtractor())->extractFromString($content);
        self::assertNotEmpty($signatures, $file);
        $range = $signatures[0]->metadata->range;
        self::assertNotNull($range, $file);

        self::assertSame(
            $expected,
            (new DocMdpValidationDataInspector())->hasOnlyValidationDataUpdates(
                $content,
                $range['length2'],
            ),
            $file,
        );
    }
}
