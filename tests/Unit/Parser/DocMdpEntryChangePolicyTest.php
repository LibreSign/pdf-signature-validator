<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Tests\Unit\Parser;

use LibreSign\PdfSignatureValidator\Parser\DocMdpEntryChangePolicy;
use LibreSign\PdfSignatureValidator\Parser\DocMdpRevisionState;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DocMdpEntryChangePolicyTest extends TestCase
{
    /** @return iterable<string,array{int,array<string,string>,array<string,string>,bool}> */
    public static function changeCases(): iterable
    {
        yield 'catalog adds DSS' => [1,
            ['/Type' => '/Catalog', '/Pages' => '2 0 R'],
            ['/Type' => '/Catalog', '/Pages' => '2 0 R', '/DSS' => '8 0 R'],
            true,
        ];
        yield 'catalog changes page tree' => [1,
            ['/Type' => '/Catalog', '/Pages' => '2 0 R'],
            ['/Type' => '/Catalog', '/Pages' => '99 0 R', '/DSS' => '8 0 R'],
            false,
        ];
        yield 'catalog adds OpenAction' => [1,
            ['/Type' => '/Catalog', '/Pages' => '2 0 R'],
            ['/Type' => '/Catalog', '/Pages' => '2 0 R', '/OpenAction' => '5 0 R'],
            false,
        ];
        yield 'page only appends timestamp annotation' => [3,
            ['/Type' => '/Page', '/Annots' => '[4 0 R]'],
            ['/Type' => '/Page', '/Annots' => '[4 0 R 8 0 R]'],
            true,
        ];
        yield 'page replaces existing annotation' => [3,
            ['/Type' => '/Page', '/Annots' => '[4 0 R]'],
            ['/Type' => '/Page', '/Annots' => '[8 0 R]'],
            false,
        ];
        yield 'page appends unrelated annotation' => [3,
            ['/Type' => '/Page', '/Annots' => '[4 0 R]'],
            ['/Type' => '/Page', '/Annots' => '[4 0 R 9 0 R]'],
            false,
        ];
        yield 'unrecognized object cannot be rewritten' => [2,
            ['/Type' => '/Pages', '/Count' => '1'],
            ['/Type' => '/Pages', '/Count' => '2'],
            false,
        ];
    }

    #[DataProvider('changeCases')]
    public function testOnlyAllowsWhitelistedExistingObjectChanges(
        int $number,
        array $before,
        array $after,
        bool $allowed,
    ): void {
        $state = new DocMdpRevisionState(1, null, null, null);
        $timestamps = ['8 0 R' => true];

        self::assertSame(
            $allowed,
            (new DocMdpEntryChangePolicy())->allowsChangedEntries($state, $number, $before, $after, $timestamps),
        );
    }
}
