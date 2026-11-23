<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy\DssChangeRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DssChangeRuleTest extends TestCase
{
    /** @return iterable<string,array{array<string,string>,int,bool}> */
    public static function dssCases(): iterable
    {
        yield 'DSS with certificate reference' => [['/Type' => '/DSS', '/Certs' => '[9 0 R]'], 0, true];
        yield 'DSS created in a future revision' => [['/Type' => '/DSS', '/Certs' => '[9 0 R]'], 1, false];
        yield 'DSS without validation entries' => [['/Type' => '/DSS'], 0, false];
        yield 'DSS with unrecognized entry' => [['/Type' => '/DSS', '/Certs' => '[]', '/OpenAction' => '8 0 R'], 0, false];
    }

    #[DataProvider('dssCases')]
    public function testRequiresAnActualDssObjectInTheCurrentRevision(
        array $dictionary,
        int $introducedAt,
        bool $expected,
    ): void {
        self::assertSame(
            $expected,
            (new DssChangeRule())->allowsNewDss(
                '8 0 R',
                [8 => $this->object(8, $dictionary)],
                [8 => $introducedAt],
                0,
            ),
        );
    }

    /** @param array<string,string> $entries
     * @return array{num:int,gen:int,value:string,entries:array<string,string>,stream:null,end:int}
     */
    private function object(int $number, array $entries): array
    {
        return [
            'num' => $number,
            'gen' => 0,
            'value' => '<<>>',
            'entries' => $entries,
            'stream' => null,
            'end' => 0,
        ];
    }
}
