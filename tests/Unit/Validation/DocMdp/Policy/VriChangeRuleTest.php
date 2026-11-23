<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy\VriChangeRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class VriChangeRuleTest extends TestCase
{
    private const string HASH = '/1626DC05376D0FAC1FCC3ED62DF0A599FCB2C1AC';

    /** @return iterable<string,array{string,bool}> */
    public static function vriCases(): iterable
    {
        yield 'actual pyHanko VRI structure' => ['<< ' . self::HASH . ' 15 0 R >>', true];
        yield 'null VRI value' => ['null', false];
        yield 'unknown VRI key' => ['<< /BROKEN null >>', false];
        yield 'empty VRI' => ['<<>>', false];
        yield 'missing VRI record' => ['<< ' . self::HASH . ' 88 0 R >>', false];
        yield 'wrong VRI record generation' => ['<< ' . self::HASH . ' 15 1 R >>', false];
    }

    #[DataProvider('vriCases')]
    public function testRejectsUnverifiedVriStructures(string $value, bool $expected): void
    {
        $objects = [
            14 => $this->object(14, ['/Length' => '4'], 'DATA'),
            15 => $this->object(15, ['/Type' => '/VRI', '/Cert' => '[14 0 R]']),
        ];

        self::assertSame(
            $expected,
            (new VriChangeRule())->allowsVri($value, $objects, [14 => 0, 15 => 0], 0),
        );
    }

    public function testRejectsMalformedVriEvidenceStream(): void
    {
        $value = '<< ' . self::HASH . ' 15 0 R >>';
        $objects = [
            14 => $this->object(14, ['/Type' => '/Action'], null),
            15 => $this->object(15, ['/Type' => '/VRI', '/Cert' => '[14 0 R]']),
        ];

        self::assertFalse((new VriChangeRule())->allowsVri($value, $objects, [14 => 0, 15 => 0], 0));
    }

    /** @param array<string,string> $entries
     * @return array{num:int,gen:int,value:string,entries:array<string,string>,stream:?string,end:int}
     */
    private function object(int $number, array $entries, ?string $stream = null): array
    {
        return [
            'num' => $number,
            'gen' => 0,
            'value' => '<<>>',
            'entries' => $entries,
            'stream' => $stream,
            'end' => 0,
        ];
    }
}
