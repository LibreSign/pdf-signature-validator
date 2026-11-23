<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Pdf\Syntax;

use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfSyntaxReader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PdfSyntaxReaderTest extends TestCase
{
    /** @return iterable<string,array{string,string}> */
    public static function canonicalValueProvider(): iterable
    {
        yield 'dictionary keys are ordered' => ['<< /B 2 /A 1 >>', '<</A 1 /B 2>>'];
        yield 'object references remain distinct' => ['[1 0 R 2 0 R]', '[1 0 R 2 0 R]'];
        yield 'escaped PDF name is decoded' => ['/Obj#53tm', '/ObjStm'];
        yield 'literal string escapes compare by bytes' => ['(Line\nTwo)', '<4c696e650a54776f>'];
        yield 'odd hexadecimal string is padded' => ['<ABC>', '<abc0>'];
        yield 'nested literal string' => ['((abc))', '<2861626329>'];
    }

    #[DataProvider('canonicalValueProvider')]
    public function testCanonicalizesPdfValues(string $pdf, string $expected): void
    {
        $offset = 0;
        $actual = (new PdfSyntaxReader())->readPdfValue($pdf, $offset, 0);

        self::assertSame($expected, $actual);
        self::assertSame(strlen($pdf), $offset);
    }

    /** @return iterable<string,array{string}> */
    public static function malformedValueProvider(): iterable
    {
        yield 'duplicate dictionary keys' => ['<< /Type /DSS /Type /Sig >>'];
        yield 'invalid hex characters' => ['<ABCZ>'];
        yield 'unterminated array' => ['[1 0 R'];
        yield 'unterminated literal string' => ['(unfinished'];
        yield 'excessive nesting' => [str_repeat('[', 80) . '1' . str_repeat(']', 80)];
    }

    #[DataProvider('malformedValueProvider')]
    public function testRejectsMalformedPdfValues(string $value): void
    {
        $offset = 0;
        self::assertNull((new PdfSyntaxReader())->readPdfValue($value, $offset, 0));
    }

    public function testSkipsPdfCommentsWithoutTreatingThemAsObjects(): void
    {
        $pdf = " \n% /Type /Sig in a comment\n/Type";
        $offset = 0;

        self::assertSame('/Type', (new PdfSyntaxReader())->readPdfValue($pdf, $offset, 0));
        self::assertSame(strlen($pdf), $offset);
    }
}
