<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use RuntimeException;
use SignerPHP\PdfCore\PdfValue\PDFValueObject;

/**
 * Structural /ByteRange validator for a signature reached from the active
 * object graph. This class does not extract PDF bytes or verify cryptography.
 *
 * @internal
 */
final class SignatureByteRangeReader
{
    /**
     * The /ByteRange is a list of (offset, length) pairs, usually two (ISO
     * 32000-1, table 252). Pairs that overlap or end after the file cannot
     * describe the bytes that were signed.
     * @return non-empty-list<array{offset:int,length:int}>
     */
    public function read(PdfObjectResolver $resolver, PDFValueObject $signature, int $fileSize): array
    {
        $byteRange = $resolver->integers($resolver->get($signature, 'ByteRange'));
        if (count($byteRange) < 4 || count($byteRange) % 2 !== 0 || $byteRange[0] !== 0) {
            throw new RuntimeException('A signature /ByteRange must begin at zero and exclude its Contents.');
        }

        $end = 0;
        $ranges = [];
        foreach (array_chunk($byteRange, 2) as $index => [$offset, $length]) {
            if ($length === 0 || ($index > 0 && $offset <= $end)
                || $offset < $end || $offset > $fileSize || $length > $fileSize - $offset) {
                throw new RuntimeException('The signature /ByteRange overlaps itself or ends after the file.');
            }

            $end = $offset + $length;
            $ranges[] = ['offset' => $offset, 'length' => $length];
        }

        if ($ranges === []) {
            throw new RuntimeException('The signature /ByteRange does not contain any signed spans.');
        }

        return $ranges;
    }
}
