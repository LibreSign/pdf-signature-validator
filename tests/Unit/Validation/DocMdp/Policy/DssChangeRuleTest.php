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
                [8 => $this->object(8, $dictionary), 9 => $this->object(9, ['/Length' => '4'], 'ABCD')],
                [8 => $introducedAt, 9 => 0],
                0,
            ),
        );
    }

    /** @return iterable<string,array{string,int,int,?string,bool}> */
    public static function streamReferenceCases(): iterable
    {
        yield 'genuine referenced stream' => ['[9 0 R]', 0, 0, 'ABCD', true];
        yield 'plain object instead of stream' => ['[9 0 R]', 0, 0, null, false];
        yield 'reference to future stream' => ['[9 0 R]', 0, 1, 'ABCD', false];
        yield 'incorrect reference generation' => ['[9 1 R]', 0, 0, 'ABCD', false];
        yield 'missing referenced object' => ['[10 0 R]', 0, 0, 'ABCD', false];
        yield 'inline hexadecimal data is not a stream reference' => ['[<ABCD>]', 0, 0, 'ABCD', false];
    }

    #[DataProvider('streamReferenceCases')]
    public function testRequiresExistingStreamObjectsForDssEvidence(
        string $array,
        int $generation,
        int $introducedAt,
        ?string $stream,
        bool $expected,
    ): void {
        $dss = ['/Type' => '/DSS', '/Certs' => $array];
        $material = $this->object(9, ['/Length' => '4'], $stream);
        $material['gen'] = $generation;

        self::assertSame($expected, (new DssChangeRule())->allowsNewDss(
            '8 0 R',
            [8 => $this->object(8, $dss), 9 => $material],
            [8 => 0, 9 => $introducedAt],
            0,
        ));
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
