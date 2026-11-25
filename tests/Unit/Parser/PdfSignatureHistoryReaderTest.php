<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Parser\PdfSignatureHistoryReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PdfSignatureHistoryReaderTest extends TestCase
{
    private const CATALOG = '<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R /Perms << /DocMDP 5 0 R >> >>';

    private function certified(): string
    {
        return SyntheticPdf::pdf([
            1 => self::CATALOG,
            4 => '<< /Fields [7 0 R] >>',
            5 => SyntheticPdf::signature(2),
            7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
        ]);
    }

    public function testUnsignedAndOrphanAreNotCertifications(): void
    {
        foreach ([[], [5 => SyntheticPdf::signature(1)]] as $extra) {
            $pdf = SyntheticPdf::pdf([1 => '<< /Type /Catalog /Pages 2 0 R >>'] + $extra);
            $history = (new PdfSignatureHistoryReader())->readFromString($pdf);
            self::assertTrue($history->isConclusive);
            self::assertNull($history->permission);
            self::assertNull($history->certification);
        }
    }

    public function testTruncatedHistoryIsInconclusive(): void
    {
        $history = (new PdfSignatureHistoryReader())->readFromString(substr($this->certified(), 0, -12));
        self::assertFalse($history->isConclusive);
    }

    /** @return iterable<string,array{string,?int,int}> */
    public static function realHistoryCases(): iterable
    {
        yield 'DSS P=1' => ['docmdp/pyhanko-p1-dss.pdf', 1, 1];
        yield 'DSS P=2' => ['docmdp/pyhanko-p2-dss.pdf', 2, 1];
        yield 'DSS P=3' => ['docmdp/pyhanko-p3-dss.pdf', 3, 1];
        yield 'document timestamp' => ['docmdp/pyhanko-p1-timestamp.pdf', 1, 2];
        yield 'approval after certification' => ['pdfs/real_pyhanko_certification_then_approval.pdf', 2, 2];
    }

    #[DataProvider('realHistoryCases')]
    public function testRealHistories(string $path, ?int $permission, int $count): void
    {
        $content = file_get_contents(__DIR__ . '/../../Fixtures/' . $path);
        self::assertIsString($content);
        $history = (new PdfSignatureHistoryReader())->readFromString($content);
        self::assertTrue($history->isConclusive);
        self::assertSame($permission, $history->permission?->value);
        self::assertCount($count, $history->current->activeSignatures);
    }

    public function testApprovalBeforeCertificationIsNotConclusive(): void
    {
        $content = file_get_contents(__DIR__ . '/../../Fixtures/pdfs/real_pyhanko_approval_then_certification.pdf');
        self::assertIsString($content);
        self::assertFalse((new PdfSignatureHistoryReader())->readFromString($content)->isConclusive);
    }
}
