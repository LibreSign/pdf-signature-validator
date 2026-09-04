<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Parser;

use LibreSign\PdfSignatureValidator\Model\DocumentModificationState;
use LibreSign\PdfSignatureValidator\Model\ExtractedSignature;
use LibreSign\PdfSignatureValidator\Model\SignatureMetadata;

final class PdfDocumentModificationAnalyzer
{
    /**
     * @param list<ExtractedSignature> $signatures
     * @return list<ExtractedSignature>
     */
    public function enrichLastSignatureMetadata(array $signatures, string $content): array
    {
        if ($signatures === []) {
            return $signatures;
        }

        $lastSignatureIndex = $this->findLastSignatureIndex($signatures);
        if ($lastSignatureIndex === null) {
            return $signatures;
        }

        $state = $this->detectDocumentModificationState(
            $signatures[$lastSignatureIndex]->metadata,
            $content,
        );

        $enrichedSignatures = [];

        foreach ($signatures as $index => $signature) {
            $metadata = $signature->metadata;

            $enrichedSignatures[] = new ExtractedSignature(
                $signature->binarySignature,
                new SignatureMetadata(
                    $metadata->field,
                    $metadata->range,
                    $metadata->signatureType,
                    $metadata->coversEntireDocument,
                    $metadata->contentsOffset,
                    $index === $lastSignatureIndex ? $state : null,
                ),
                $signature->hashAlgorithm,
            );
        }

        return $enrichedSignatures;
    }

    /**
     * @param list<ExtractedSignature> $signatures
     */
    private function findLastSignatureIndex(array $signatures): ?int
    {
        $lastSignatureIndex = null;
        $lastStructuralOffset = -1;

        foreach ($signatures as $index => $signature) {
            $metadata = $signature->metadata;

            $structuralOffset = $metadata->contentsOffset;
            if ($structuralOffset === null && $metadata->range !== null) {
                $structuralOffset = $metadata->range['length1'];
            }

            if ($structuralOffset === null) {
                continue;
            }

            if ($structuralOffset > $lastStructuralOffset) {
                $lastStructuralOffset = $structuralOffset;
                $lastSignatureIndex = $index;
            }
        }

        return $lastSignatureIndex;
    }

    private function detectDocumentModificationState(
        SignatureMetadata $metadata,
        string $content,
    ): DocumentModificationState {
        $range = $metadata->range;

        if (!$this->isValidByteRange(
            $range,
            $metadata->contentsOffset,
            $content,
        )) {
            return DocumentModificationState::INVALID_BYTE_RANGE;
        }

        if ($range === null) {
            return DocumentModificationState::INVALID_BYTE_RANGE;
        }

        $signedEnd = $range['length2'];

        if (!$this->endsAtSignedEofBoundary($content, $signedEnd)) {
            return DocumentModificationState::INVALID_EOF_BOUNDARY;
        }

        $unsignedContent = substr($content, $signedEnd);

        if ($this->isOptionalEol($unsignedContent)) {
            return DocumentModificationState::UNCHANGED;
        }

        $lastEofOffset = strrpos($content, '%%EOF');
        if ($lastEofOffset === false) {
            return DocumentModificationState::UNSIGNED_CONTENT;
        }

        $afterFinalEof = substr(
            $content,
            $lastEofOffset + strlen('%%EOF'),
        );

        if (!$this->isOptionalEol($afterFinalEof)) {
            return DocumentModificationState::TRAILING_DATA;
        }

        return DocumentModificationState::UNSIGNED_CONTENT;
    }

    /**
     * @param array{offset1:int,length1:int,offset2:int,length2:int}|null $range
     */
    private function isValidByteRange(
        ?array $range,
        ?int $contentsOffset,
        string $content,
    ): bool {
        if ($range === null) {
            return false;
        }

        return $this->hasValidRangeBounds($range, strlen($content))
            && $this->matchesContentsGap(
                $range,
                $contentsOffset,
                $content,
            );
    }

    /**
     * @param array{offset1:int,length1:int,offset2:int,length2:int} $range
     */
    private function hasValidRangeBounds(array $range, int $fileSize): bool
    {
        if ($range['offset1'] !== 0) {
            return false;
        }

        if ($this->hasNegativeRangeValue($range)) {
            return false;
        }

        if ($range['length1'] >= $range['offset2']) {
            return false;
        }

        if ($range['offset2'] >= $range['length2']) {
            return false;
        }

        return $range['length2'] <= $fileSize;
    }

    /**
     * @param array{offset1:int,length1:int,offset2:int,length2:int} $range
     */
    private function hasNegativeRangeValue(array $range): bool
    {
        return $range['length1'] < 0
            || $range['offset2'] < 0
            || $range['length2'] < 0;
    }

    /**
     * @param array{offset1:int,length1:int,offset2:int,length2:int} $range
     */
    private function matchesContentsGap(
        array $range,
        ?int $contentsOffset,
        string $content,
    ): bool {
        if ($contentsOffset === null) {
            return true;
        }

        if ($contentsOffset <= 0) {
            return false;
        }

        $openingDelimiterOffset = $contentsOffset - 1;

        if (($content[$openingDelimiterOffset] ?? null) !== '<') {
            return false;
        }

        $closingDelimiterOffset = strpos(
            $content,
            '>',
            $contentsOffset,
        );

        if ($closingDelimiterOffset === false) {
            return false;
        }

        return $range['length1'] === $openingDelimiterOffset
            && $range['offset2'] === $closingDelimiterOffset + 1;
    }

    private function endsAtSignedEofBoundary(string $content, int $signedEnd): bool
    {
        $signedRevision = substr($content, 0, $signedEnd);

        return preg_match(
            '/%%EOF(?:\r\n|\r|\n)?\z/D',
            $signedRevision,
        ) === 1;
    }

    private function isOptionalEol(string $content): bool
    {
        return in_array(
            $content,
            ['', "\n", "\r", "\r\n"],
            true,
        );
    }
}
