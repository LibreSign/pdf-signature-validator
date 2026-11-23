<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Pdf\Revision;

use LibreSign\PdfSignatureValidator\Pdf\Revision\PdfRevisionTrailerPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PdfRevisionTrailerPolicyTest extends TestCase
{
    /** @return iterable<string,array{array<string,string>,array<string,string>,bool}> */
    public static function additionalInfoCases(): iterable
    {
        $trailer = ['/Prev' => '123', '/Root' => '1 0 R', '/Size' => '9', '/Info' => '8 0 R'];
        yield 'valid Producer and ModDate' => [
            $trailer, ['/ModDate' => '<443a32303236>', '/Producer' => '<707968616e6b6f>'], true,
        ];
        yield 'modification to Title is forbidden' => [
            $trailer, ['/Title' => '<4d616c6963696f7573>'], false,
        ];
        yield 'action-like metadata is forbidden' => [
            $trailer, ['/OpenAction' => '9 0 R'], false,
        ];
        yield 'Info may not point to a pre-certification object' => [
            array_replace($trailer, ['/Info' => '4 0 R']), ['/Producer' => '<64617461>'], false,
        ];
        yield 'invalid Info generation is rejected' => [
            array_replace($trailer, ['/Info' => '8 1 R']), ['/Producer' => '<64617461>'], false,
        ];
        yield 'new Info must be present' => [
            array_replace($trailer, ['/Info' => '99 0 R']), ['/Producer' => '<64617461>'], false,
        ];
        yield 'invalid Previous xref is rejected' => [
            array_replace($trailer, ['/Prev' => '9']), ['/Producer' => '<64617461>'], false,
        ];
        yield 'unexpected root is rejected' => [
            array_replace($trailer, ['/Root' => '4 0 R']), ['/Producer' => '<64617461>'], false,
        ];
    }

    #[DataProvider('additionalInfoCases')]
    public function testOnlyAllowsSafeFirstInfoAddition(
        array $trailer,
        array $entries,
        bool $expected,
    ): void {
        $info = [
            'num' => 8, 'gen' => 0, 'value' => '<<>>',
            'entries' => $entries, 'stream' => null, 'end' => 0,
        ];
        $signed = [
            'startxref' => 123, 'offsets' => [], 'size' => 8,
            'root' => '1 0 R', 'info' => null,
        ];
        $activeInfo = null;

        $actual = (new PdfRevisionTrailerPolicy())->matches(
            $trailer,
            123,
            $signed,
            [8 => $info],
            $activeInfo,
        );

        self::assertSame($expected, $actual);
        self::assertSame($expected ? '8 0 R' : null, $activeInfo);
    }

    public function testDoesNotAllowReplacingAnInfoObjectAgain(): void
    {
        $trailer = ['/Prev' => '123', '/Root' => '1 0 R', '/Info' => '9 0 R'];
        $signed = [
            'startxref' => 123, 'offsets' => [], 'size' => 8,
            'root' => '1 0 R', 'info' => null,
        ];
        $info = [
            'num' => 9, 'gen' => 0, 'value' => '<<>>',
            'entries' => ['/Producer' => '<64617461>'], 'stream' => null, 'end' => 0,
        ];
        $activeInfo = '8 0 R';

        self::assertFalse((new PdfRevisionTrailerPolicy())->matches(
            $trailer,
            123,
            $signed,
            [9 => $info],
            $activeInfo,
        ));
        self::assertSame('8 0 R', $activeInfo);
    }
}
