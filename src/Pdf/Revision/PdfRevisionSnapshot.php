<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

/**
 * Read-only view of the certifying revision and all subsequent revisions.
 *
 * @psalm-type PdfObject array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int}
 * @psalm-type SignedRevision array{startxref:int,offsets:array<int,int>,size:int,root:string,info:?string,compressedObjects?:array<int,array{num:int,gen:int,value:string,entries:?array<string,string>,stream:null,end:int}>}
 * @phpstan-type PdfObject array{num:int,gen:int,value:string,entries:?array<string,string>,stream:?string,end:int}
 * @phpstan-type SignedRevision array{startxref:int,offsets:array<int,int>,size:int,root:string,info:?string,compressedObjects?:array<int,array{num:int,gen:int,value:string,entries:?array<string,string>,stream:null,end:int}>}
 */
final class PdfRevisionSnapshot
{
    /**
     * @param SignedRevision $signed
     * @param list<array<int, PdfObject>> $revisions
     */
    public function __construct(
        public readonly string $content,
        public readonly array $signed,
        public readonly array $revisions,
        private readonly PdfIncrementalRevisionReader $reader,
    ) {
    }

    /** @return PdfObject|null */
    public function signedObject(int $number): ?array
    {
        return $this->reader->readSignedObject($this->content, $this->signed, $number);
    }
}
