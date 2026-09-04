<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

declare(strict_types=1);

namespace LibreSign\PdfSignatureValidator\Model;

enum DocumentModificationState: string
{
    case FULLY_COVERED = 'fully_covered';
    case UNSIGNED_CONTENT = 'unsigned_content';
    case TRAILING_DATA = 'trailing_data';
    case INVALID_BYTE_RANGE = 'invalid_byte_range';
}
