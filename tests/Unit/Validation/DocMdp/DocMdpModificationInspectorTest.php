<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Validation\DocMdp;

use LibreSign\PdfSignatureValidator\Model\DocMdpPermission;
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureInventoryReader;
use LibreSign\PdfSignatureValidator\Tests\Unit\Parser\SyntheticPdf;
use LibreSign\PdfSignatureValidator\Validation\DocMdp\DocMdpModificationInspector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DocMdpModificationInspectorTest extends TestCase
{
    private const CATALOG = '<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R /Perms << /DocMDP 5 0 R >> >>';
    private const PAGE = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] /Contents 8 0 R /Annots [9 0 R 10 0 R] >>';
    private const FORM = '<< /Fields [7 0 R 9 0 R] /SigFlags 3 >>';
    private const FIELD = '<< /Type /Annot /Subtype /Widget /FT /Tx /T (Name) /V (before) /Rect [10 10 80 30] /P 3 0 R /AP << /N 11 0 R >> >>';
    private const ANNOTATION = '<< /Type /Annot /Subtype /Text /Rect [100 100 120 120] /Contents (note) /P 3 0 R >>';

    private static function stream(string $bytes, string $entries = ''): string
    {
        return '<< /Length ' . strlen($bytes) . ' ' . $entries . " >>\nstream\n" . $bytes . "\nendstream";
    }

    private function signed(int $level): string
    {
        return SyntheticPdf::pdf([
            1 => self::CATALOG,
            3 => self::PAGE,
            4 => self::FORM,
            5 => SyntheticPdf::signature($level),
            7 => '<< /FT /Sig /T (Certification) /V 5 0 R >>',
            8 => self::stream('BT (original) Tj ET'),
            9 => self::FIELD,
            10 => self::ANNOTATION,
            11 => self::stream('BT (before) Tj ET', '/Type /XObject /Subtype /Form /BBox [0 0 70 20] /Resources <<>>'),
        ]);
    }

    /** @return array<int,string> */
    private static function fill(): array
    {
        return [9 => str_replace('(before)', '(after)', self::FIELD)];
    }

    /** @return array<int,string> */
    private static function approval(): array
    {
        return [
            4 => str_replace('9 0 R]', '9 0 R 13 0 R]', self::FORM),
            12 => SyntheticPdf::signature(null),
            13 => '<< /FT /Sig /T (Approval) /V 12 0 R >>',
        ];
    }

    /** @return array<int,string> */
    private static function visibleApproval(): array
    {
        return [
            3 => str_replace('10 0 R]', '10 0 R 13 0 R]', self::PAGE),
            4 => str_replace('9 0 R]', '9 0 R 13 0 R]', self::FORM),
            12 => SyntheticPdf::signature(null),
            13 => '<< /Type /Annot /Subtype /Widget /FT /Sig /T (Approval) /V 12 0 R /Rect [100 10 170 30] /P 3 0 R /AP << /N 14 0 R >> >>',
            14 => self::stream('BT (Approval) Tj ET', '/Type /XObject /Subtype /Form /BBox [0 0 70 20] /Resources <<>>'),
        ];
    }

    /** @return array<int,string> */
    private static function dss(): array
    {
        return [
            1 => str_replace('/AcroForm', '/DSS 20 0 R /AcroForm', self::CATALOG),
            20 => '<< /Type /DSS /Certs [21 0 R] >>',
            21 => self::stream('synthetic evidence'),
        ];
    }

    /** @return array<int,string> */
    private static function annotation(): array
    {
        return [
            3 => str_replace('10 0 R]', '10 0 R 15 0 R]', self::PAGE),
            15 => '<< /Type /Annot /Subtype /Text /Rect [150 100 170 120] /Contents (new note) /P 3 0 R >>',
        ];
    }

    /** @return array<int,string> */
    private static function timestamp(): array
    {
        return [
            3 => str_replace('10 0 R]', '10 0 R 17 0 R]', self::PAGE),
            4 => str_replace('9 0 R]', '9 0 R 17 0 R]', self::FORM),
            16 => str_replace(
                ['/Type /Sig ', '/adbe.pkcs7.detached'],
                ['/Type /DocTimeStamp ', '/ETSI.RFC3161'],
                SyntheticPdf::signature(null),
            ),
            17 => '<< /Type /Annot /Subtype /Widget /FT /Sig /T (Timestamp) /V 16 0 R /Rect [0 0 0 0] /F 132 /P 3 0 R >>',
        ];
    }

    /** @return iterable<string,array{int,list<array<int,string>>,bool}> */
    public static function cases(): iterable
    {
        foreach ([1, 2, 3] as $level) {
            yield "P=$level form value" => [$level, [self::fill()], $level >= 2];
            yield "P=$level approval" => [$level, [self::approval()], $level >= 2];
            yield "P=$level visible approval" => [$level, [self::visibleApproval()], $level >= 2];
            yield "P=$level annotation addition" => [$level, [self::annotation()], $level === 3];
            yield "P=$level annotation edit" => [$level, [[10 => str_replace('(note)', '(changed)', self::ANNOTATION)]], $level === 3];
            yield "P=$level annotation removal" => [$level, [[3 => str_replace(' 10 0 R', '', self::PAGE)]], $level === 3];
            yield "P=$level DSS" => [$level, [self::dss()], true];
            yield "P=$level timestamp" => [$level, [self::timestamp()], true];
            yield "P=$level DSS plus form fill" => [$level, [self::dss() + self::fill()], $level >= 2];
            yield "P=$level approval plus DSS" => [$level, [self::approval() + self::dss()], $level >= 2];
            yield "P=$level timestamp plus form fill" => [$level, [self::timestamp() + self::fill()], $level >= 2];
            yield "P=$level annotation plus form fill" => [$level, [self::annotation() + self::fill()], $level === 3];
            yield "P=$level approval after DSS" => [$level, [self::dss(), self::approval()], $level >= 2];
            yield "P=$level DSS after form fill" => [$level, [self::fill(), self::dss()], $level >= 2];
            yield "P=$level page content edit" => [$level, [[8 => self::stream('BT (changed) Tj ET')]], false];
        }
    }

    #[DataProvider('cases')]
    public function testStructuralPolicy(int $level, array $updates, bool $expected): void
    {
        $signed = $this->signed($level);
        $updated = $signed;
        foreach ($updates as $revision) {
            $updated = SyntheticPdf::incrementalUpdate($updated, $revision);
        }
        self::assertSame($expected, (new DocMdpModificationInspector())->allows(
            $updated,
            strlen($signed),
            DocMdpPermission::from($level),
        ));
    }

    /** @return iterable<string,array{string,bool}> */
    public static function corpusCases(): iterable
    {
        yield from DocMdpCorpusTest::certifiedPdfCases();
        yield 'real approval after certification' => ['../pdfs/real_pyhanko_certification_then_approval.pdf', true];
    }

    #[DataProvider('corpusCases')]
    public function testExistingRealSignedCorpus(string $file, bool $expected): void
    {
        $content = file_get_contents(__DIR__ . '/../../../Fixtures/docmdp/' . $file);
        self::assertIsString($content);
        $inventory = (new PdfSignatureInventoryReader())->readFromString($content);
        self::assertTrue($inventory->isConclusive);
        self::assertNotNull($inventory->docMdpPermission);
        $signature = array_values(array_filter($inventory->activeSignatures, static fn (\LibreSign\PdfSignatureValidator\Model\ActiveSignature $sig): bool => $sig->isCertifying))[0];
        self::assertSame($expected, (new DocMdpModificationInspector())->allows(
            $content,
            $signature->signedRevisionEnd,
            $inventory->docMdpPermission,
        ), $file);
    }
}
