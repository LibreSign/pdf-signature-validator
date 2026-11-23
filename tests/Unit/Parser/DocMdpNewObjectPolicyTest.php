<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Parser\DocMdpNewObjectPolicy;
use LibreSign\PdfSignatureValidator\Parser\DocMdpRevisionState;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DocMdpNewObjectPolicyTest extends TestCase
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
            (new DocMdpNewObjectPolicy())->isNewDssDictionary(
                '8 0 R',
                [8 => $this->object(8, $dictionary)],
                [8 => $introducedAt],
                0,
            ),
        );
    }

    /** @return iterable<string,array{array<string,string>,bool}> */
    public static function newObjectTypes(): iterable
    {
        yield 'ordinary DSS metadata' => [['/Type' => '/DSS', '/Certs' => '[]'], true];
        yield 'new approval signature' => [['/Type' => '/Sig'], false];
        yield 'hidden object stream' => [['/Type' => '/ObjStm'], false];
        yield 'xref stream' => [['/Type' => '/XRef'], false];
        yield 'approval signature without type' => [['/ByteRange' => '[0 1 2 3]'], false];
        yield 'timestamp without contents' => [['/Type' => '/DocTimeStamp', '/SubFilter' => '/ETSI.RFC3161', '/ByteRange' => '[0 1 2 3]'], false];
        yield 'document timestamp' => [['/Type' => '/DocTimeStamp', '/SubFilter' => '/ETSI.RFC3161', '/ByteRange' => '[0 1 2 3]', '/Contents' => '<00>'], true];
        yield 'new annotation not exempt' => [['/Type' => '/Annot'], false];
    }

    #[DataProvider('newObjectTypes')]
    public function testClassifiesNewPdfObjectsStrictly(array $entries, bool $expected): void
    {
        $state = new DocMdpRevisionState(1, null, null, null);
        $state->newObjects[8] = $this->object(8, $entries);
        $state->newObjectRevisions[8] = 0;

        self::assertSame($expected, (new DocMdpNewObjectPolicy())->validateNewObjects($state));
    }
    public function testRejectsTimestampFieldThatReferencesAnObjectFromALaterRevision(): void
    {
        $state = new DocMdpRevisionState(1, null, null, null);
        $state->newObjects = [
            8 => $this->object(8, [
                '/FT' => '/Sig', '/Type' => '/Annot', '/Subtype' => '/Widget',
                '/Rect' => '[0 0 0 0]', '/V' => '9 0 R',
            ]),
            9 => $this->object(9, [
                '/Type' => '/DocTimeStamp', '/SubFilter' => '/ETSI.RFC3161',
                '/ByteRange' => '[0 1 2 3]', '/Contents' => '<00>',
            ]),
        ];
        $state->newObjectRevisions = [8 => 0, 9 => 1];

        self::assertFalse((new DocMdpNewObjectPolicy())->validateNewObjects($state));
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
