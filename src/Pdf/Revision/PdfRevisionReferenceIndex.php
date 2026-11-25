<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfReferencePaths;

/** Reverse reference index for the live objects of a PDF revision. */
final class PdfRevisionReferenceIndex
{
    public function __construct(private readonly PdfReferencePaths $reader = new PdfReferencePaths())
    {
    }

    /** @return array<int,list<array{owner:int,path:string}>>|null */
    public function read(PdfRevisionObjects $document): ?array
    {
        $incoming = [];
        foreach ($document->objects as $owner => $object) {
            $paths = $this->reader->read($object['value']);
            if ($paths === null) {
                return null;
            }
            foreach ($paths as $path) {
                $target = $document->resolve($path['reference']);
                if ($target !== null) {
                    $incoming[$target['num']][] = ['owner' => $owner, 'path' => $path['path']];
                }
            }
        }

        return $incoming;
    }
}
