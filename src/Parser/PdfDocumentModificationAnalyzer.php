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
            $signatures[$lastSignatureIndex]->metadata->range,
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
        $lastContentsOffset = -1;

        foreach ($signatures as $index => $signature) {
            $contentsOffset = $signature->metadata->signatureOffset;
            if ($contentsOffset === null) {
                continue;
            }

            if ($contentsOffset > $lastContentsOffset) {
                $lastContentsOffset = $contentsOffset;
                $lastSignatureIndex = $index;
            }
        }

        if ($lastSignatureIndex !== null) {
            return $lastSignatureIndex;
        }

        $lastSignedOffset = -1;

        foreach ($signatures as $index => $signature) {
            $range = $signature->metadata->range;
            if ($range === null) {
                continue;
            }

            if ($range['length2'] > $lastSignedOffset) {
                $lastSignedOffset = $range['length2'];
                $lastSignatureIndex = $index;
            }
        }

        return $lastSignatureIndex;
    }

    /**
     * @param array{offset1:int,length1:int,offset2:int,length2:int}|null $range
     */
    private function detectDocumentModificationState(
        ?array $range,
        string $content,
    ): DocumentModificationState {
        if ($range === null) {
            return DocumentModificationState::INVALID_BYTE_RANGE;
        }

        if (!$this->isValidByteRange($range, strlen($content))) {
            return DocumentModificationState::INVALID_BYTE_RANGE;
        }

        $unsignedContent = substr($content, $range['length2']);

        if (!$this->hasNonPdfWhitespace($unsignedContent)) {
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

        if ($this->hasNonPdfWhitespace($afterFinalEof)) {
            return DocumentModificationState::TRAILING_DATA;
        }

        return DocumentModificationState::UNSIGNED_CONTENT;
    }

    private function hasNonPdfWhitespace(string $content): bool
    {
        return preg_match('/[^\\x00\\x09\\x0A\\x0C\\x0D\\x20]/', $content) === 1;
    }

    /**
     * @param array{offset1:int,length1:int,offset2:int,length2:int} $range
     */
    private function isValidByteRange(array $range, int $fileSize): bool
    {
        if ($range['offset1'] !== 0) {
            return false;
        }

        if ($range['length1'] > $range['offset2']) {
            return false;
        }

        if ($range['offset2'] > $fileSize) {
            return false;
        }

        if ($range['length2'] < $range['offset2']) {
            return false;
        }

        return $range['length2'] <= $fileSize;
    }
}
