<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

enum ValidationReason: string
{
    case DIGEST_MISMATCH = 'digest_mismatch';
    case NO_BYTE_RANGE = 'no_byte_range';
    case NO_BINARY_SIGNATURE = 'no_binary_signature';
    case SIGNATURE_CERTIFICATE_MISMATCH = 'signature_certificate_mismatch';
    case INVALID_BYTE_RANGE = 'invalid_byte_range';
    case INVALID_EOF_BOUNDARY = 'invalid_eof_boundary';
    case UNSUPPORTED_SUBFILTER = 'unsupported_subfilter';
}
