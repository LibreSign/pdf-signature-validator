<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use InvalidArgumentException;
use LibreSign\PdfSignatureValidator\Exception\UnsignedPdfException;
use LibreSign\PdfSignatureValidator\Model\ExtractedSignature;
use LibreSign\PdfSignatureValidator\Model\SignatureMetadata;

final class PdfSignatureExtractor
{
    public function __construct(private CmsHashAlgorithmExtractor $hashAlgorithmExtractor = new CmsHashAlgorithmExtractor())
    {
    }

    /**
     * @param resource $resource
     * @return list<ExtractedSignature>
     */
    public function extractFromResource($resource): array
    {
        /** @psalm-suppress DocblockTypeContradiction */
        if (!is_resource($resource)) {
            throw new InvalidArgumentException('Expected stream resource.');
        }

        rewind($resource);
        $content = (string) stream_get_contents($resource);
        return $this->extractFromString($content);
    }

    /**
     * @return list<ExtractedSignature>
     */
    public function extractFromString(string $content): array
    {
        preg_match_all('/\/Contents\s*<([0-9a-fA-F]+)>/', $content, $contents, PREG_OFFSET_CAPTURE);
        if ($contents[1] === []) {
            throw new UnsignedPdfException('Unsigned file.');
        }

        $results = [];
        $seenHexSignatures = [];
        $fileSize = strlen($content);

        foreach ($contents[1] as $match) {
            $signatureHex = $match[0];
            $signatureOffset = $match[1];

            if (isset($seenHexSignatures[$signatureHex])) {
                continue;
            }
            $seenHexSignatures[$signatureHex] = true;

            [$objectStart, $objectEnd] = $this->findPdfObjectBoundaries($content, $signatureOffset);
            $signatureObject = ($objectStart !== null && $objectEnd !== null)
                ? substr($content, $objectStart, $objectEnd - $objectStart)
                : '';

            $range = $this->extractRange($signatureObject);
            $field = $this->extractField($content, $signatureObject);
            $signatureType = $this->extractSignatureType($signatureObject);
            $coversEntireDocument = $this->coversEntireDocument($range, $fileSize);

            $binarySignature = $this->decodeHexSignature($signatureHex);
            $hashAlgorithm = $this->hashAlgorithmExtractor->extract($binarySignature);

            $results[] = new ExtractedSignature(
                $binarySignature,
                new SignatureMetadata($field, $range, $signatureType, $coversEntireDocument),
                $hashAlgorithm,
            );
        }

        return $results;
    }

    /**
     * @return array{offset1:int,length1:int,offset2:int,length2:int}|null
     */
    private function extractRange(string $signatureObject): ?array
    {
        if (!preg_match('/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/', $signatureObject, $matches)) {
            return null;
        }

        $offset2 = (int) $matches[3];
        $length2 = (int) $matches[4];

        return [
            'offset1' => (int) $matches[1],
            'length1' => (int) $matches[2],
            'offset2' => $offset2,
            'length2' => $offset2 + $length2,
        ];
    }

    private function extractSignatureType(string $signatureObject): ?string
    {
        if (preg_match('/\/SubFilter\s*\/([A-Za-z0-9.\-_]+)/', $signatureObject, $matches)) {
            return $matches[1];
        }
        return null;
    }

    private function extractField(string $content, string $signatureObject): ?string
    {
        if (preg_match('/\/T\s*\((?<field>(?:\\\\.|[^)])*)\)/', $signatureObject, $fieldMatch)) {
            return $this->decodePdfString($fieldMatch['field']);
        }

        $objectId = null;
        $objectGeneration = null;
        if (preg_match('/(\d+)\s+(\d+)\s+obj/', $signatureObject, $objectRef)) {
            $objectId = $objectRef[1];
            $objectGeneration = $objectRef[2];
        }

        if ($objectId === null || $objectGeneration === null) {
            return null;
        }

        $valueRef = '\\/V\\s+' . preg_quote($objectId, '/') . '\\s+' . preg_quote($objectGeneration, '/') . '\\s+R';
        $fieldPatterns = [
            '/\\d+\\s+\\d+\\s+obj(?:(?!endobj).)*\\/T\\s*\\((?<field>(?:\\\\.|[^)])*)\\)(?:(?!endobj).)*' . $valueRef . '(?:(?!endobj).)*endobj/s',
            '/\\d+\\s+\\d+\\s+obj(?:(?!endobj).)*' . $valueRef . '(?:(?!endobj).)*\\/T\\s*\\((?<field>(?:\\\\.|[^)])*)\\)(?:(?!endobj).)*endobj/s',
        ];

        foreach ($fieldPatterns as $pattern) {
            if (preg_match($pattern, $content, $fieldRefMatch)) {
                return $this->decodePdfString($fieldRefMatch['field']);
            }
        }

        return null;
    }

    private function coversEntireDocument(?array $range, int $fileSize): bool
    {
        if ($range === null) {
            return false;
        }
        if ($range['offset1'] !== 0) {
            return false;
        }
        return $range['length2'] >= $fileSize;
    }

    /**
     * @return array{0:int|null,1:int|null}
     */
    private function findPdfObjectBoundaries(string $content, int $offset): array
    {
        $prefix = substr($content, 0, $offset);
        if ($prefix === '') {
            return [null, null];
        }

        $matchCount = preg_match_all('/\n\d+\s+\d+\s+obj\b/', $prefix, $matches, PREG_OFFSET_CAPTURE);
        if ($matchCount === 0 || $matches[0] === []) {
            return [null, null];
        }

        $lastObject = $matches[0][count($matches[0]) - 1];
        $objectStart = $lastObject[1] + 1;
        $endObjPos = strpos($content, 'endobj', $objectStart);
        if ($endObjPos === false) {
            return [null, null];
        }

        return [$objectStart, $endObjPos + strlen('endobj')];
    }

    private function decodePdfString(string $value): string
    {
        return strtr($value, [
            '\\(' => '(',
            '\\)' => ')',
            '\\\\' => '\\',
        ]);
    }

    private function decodeHexSignature(string $signatureHex): ?string
    {
        if ($signatureHex === '' || strlen($signatureHex) % 2 !== 0 || !ctype_xdigit($signatureHex)) {
            return null;
        }

        $decoded = hex2bin($signatureHex);

        return is_string($decoded) ? $decoded : null;
    }
}
