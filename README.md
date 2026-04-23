# PDF Signature Validator

Minimal PHP library to extract and validate PDF signatures.

## Requirements

- PHP 8.2+

## Install

```bash
composer require libresign/pdf-signature-validator
```

## Usage

```php
<?php

use LibreSign\PdfSignatureValidator\Parser\PdfSignatureValidator;

$validator = new PdfSignatureValidator();

$results = $validator->validateFromString($pdfBinaryContent);
// or: $results = $validator->validateFromResource($resource);
```

Each item in `$results` includes:
- `signatureValidation` (ValidationResult)
- `certificateValidation` (ValidationResult)

## Development

```bash
composer install
composer run lint
composer run cs:check
composer run phpmd
composer run phpstan
composer run psalm
composer run deptrac
composer run rector:check
composer run test:unit
```

## License

AGPL-3.0-or-later
