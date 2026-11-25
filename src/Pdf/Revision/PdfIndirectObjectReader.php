<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Pdf\Revision;

use LibreSign\PdfSignatureValidator\Pdf\Syntax\PdfSyntaxReader;

/**
 * Parses a single indirect object, resolving stream lengths only within a
 * specified signed revision.
 *
 * @psalm-import-type PdfObject from PdfIncrementalRevisionReader
 * @psalm-import-type SignedRevision from PdfIncrementalRevisionReader
 * @phpstan-import-type PdfObject from PdfIncrementalRevisionReader
 * @phpstan-import-type SignedRevision from PdfIncrementalRevisionReader
 */
final class PdfIndirectObjectReader
{
    public function __construct(private readonly PdfSyntaxReader $syntax)
    {
    }

    /**
     * @param SignedRevision $signed
     * @return PdfObject|null
     */
    public function readSignedObject(string $content, array $signed, int $num): ?array
    {
        if (isset($signed['compressedObjects'][$num])) {
            return $signed['compressedObjects'][$num];
        }
        if (!isset($signed['offsets'][$num])) {
            return null;
        }
        $object = $this->read(
            $content,
            $signed['offsets'][$num],
            fn (string $reference): ?int => $this->resolveSignedStreamLength($content, $signed, $reference),
        );
        return $object !== null && $object['num'] === $num ? $object : null;
    }

    /** @param SignedRevision $signed */
    private function resolveSignedStreamLength(string $content, array $signed, string $reference): ?int
    {
        if (!preg_match('/^(\d+) (\d+) R$/D', $reference, $match)) {
            return null;
        }
        $number = (int) $match[1];
        $generation = (int) $match[2];
        $object = $signed['compressedObjects'][$number] ?? null;
        if ($object === null && isset($signed['offsets'][$number])) {
            // A /Length object must itself be an integer, never a stream.
            // No recursive stream-length resolution is needed or permitted.
            $object = $this->read($content, $signed['offsets'][$number]);
        }
        if ($object === null || $object['num'] !== $number || $object['gen'] !== $generation
            || $object['stream'] !== null || !ctype_digit($object['value'])) {
            return null;
        }

        return (int) $object['value'];
    }

    /**
     * @param (callable(string):?int)|null $resolveLength
     * @return PdfObject|null
     */
    public function read(string $content, int $pos, ?callable $resolveLength = null): ?array
    {
        if (!preg_match('/\G(\d+)\s+(\d+)\s+obj\b/', $content, $match, 0, $pos)) {
            return null;
        }
        $pos += strlen($match[0]);
        $this->syntax->skipPdfWhitespace($content, $pos);
        $entries = null;
        $value = null;
        if (substr($content, $pos, 2) === '<<') {
            $valueStart = $pos;
            $entries = $this->syntax->readPdfDictionary($content, $pos, 0);
            $value = $entries === null ? null : $this->syntax->readPdfValue($content, $valueStart, 0);
        }
        if ($entries === null) {
            $value = $this->syntax->readPdfValue($content, $pos, 0);
        }
        if ($value === null) {
            return null;
        }
        $stream = $this->readObjectStream($content, $pos, $entries, $resolveLength);
        if ($stream === false || !preg_match('/\G\s*endobj\b/', $content, $end, 0, $pos)) {
            return null;
        }

        return [
            'num' => (int) $match[1], 'gen' => (int) $match[2],
            'value' => $value, 'entries' => $entries, 'stream' => $stream,
            'end' => $pos + strlen($end[0]),
        ];
    }

    /** @param array<string,string>|null $entries
     *  @param (callable(string):?int)|null $resolveLength
     *  @return string|false|null false means invalid stream, null means no stream */
    private function readObjectStream(string $content, int &$pos, ?array $entries, ?callable $resolveLength = null): string|false|null
    {
        if (!preg_match('/\G\s*stream(?:\r\n|\n)/', $content, $start, 0, $pos)) {
            return null;
        }
        $lengthValue = $entries['/Length'] ?? '';
        $length = ctype_digit($lengthValue) ? (int) $lengthValue : ($resolveLength === null ? null : $resolveLength($lengthValue));
        $pos += strlen($start[0]);
        if ($length === null || $length < 0 || $length > strlen($content) - $pos) {
            return false;
        }
        $stream = substr($content, $pos, $length);
        $pos += $length;
        if (strlen($stream) !== $length
            || !preg_match('/\G\s*endstream\b/', $content, $end, 0, $pos)) {
            return false;
        }
        $pos += strlen($end[0]);

        return $stream;
    }

}
