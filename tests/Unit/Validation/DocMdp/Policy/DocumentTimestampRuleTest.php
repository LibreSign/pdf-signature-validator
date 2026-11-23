<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Validation\DocMdp\Policy;

use LibreSign\PdfSignatureValidator\Validation\DocMdp\Policy\DocumentTimestampRule;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DocumentTimestampRuleTest extends TestCase
{
    /** @return iterable<string,array{array<string,string>,array<string,string>,int,bool}> */
    public static function timestampFields(): iterable
    {
        $field = [
            '/FT' => '/Sig', '/Type' => '/Annot', '/Subtype' => '/Widget',
            '/Rect' => '[0 0 0 0]', '/V' => '9 0 R',
        ];
        $timestamp = ['/Type' => '/DocTimeStamp', '/SubFilter' => '/ETSI.RFC3161'];
        yield 'valid invisible timestamp' => [$field, $timestamp, 0, true];
        yield 'future timestamp object' => [$field, $timestamp, 1, false];
        yield 'different timestamp object generation' => [array_replace($field, ['/V' => '9 1 R']), $timestamp, 0, false];
        yield 'visible field' => [array_replace($field, ['/Rect' => '[0 0 25 25]']), $timestamp, 0, false];
        yield 'widget action' => [array_replace($field, ['/A' => '10 0 R']), $timestamp, 0, false];
        yield 'nested field' => [array_replace($field, ['/Kids' => '[10 0 R]']), $timestamp, 0, false];
        yield 'approval signature instead of document timestamp' => [$field, array_replace($timestamp, ['/Type' => '/Sig']), 0, false];
    }

    #[DataProvider('timestampFields')]
    public function testOnlyAllowsInvisibleTimestampFieldsWithExistingTimestamp(
        array $field,
        array $signature,
        int $introducedAt,
        bool $expected,
    ): void {
        $timestampObject = [
            'num' => 9, 'gen' => 0, 'value' => '<<>>',
            'entries' => $signature, 'stream' => null, 'end' => 0,
        ];
        self::assertSame(
            $expected,
            (new DocumentTimestampRule())->allowsTimestampField(
                $field,
                [9 => $timestampObject],
                [9 => $introducedAt],
                0,
            ),
        );
    }
}
