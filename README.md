# PDF Signature Validator

Minimal PHP library to extract and validate PDF signatures.

## Install

```bash
composer require libresign/pdf-signature-validator
```

## Usage

```php
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureValidator;

$validator = new PdfSignatureValidator();

$results = $validator->validateFromString($pdfBinaryContent);
// or: $results = $validator->validateFromResource($resource);
```

Each item in `$results` includes:
- `signatureValidation` (ValidationResult)
- `certificateValidation` (ValidationResult)

## Development

Use the CI workflows as the source of truth. For local execution, use the scripts declared in `composer.json`.

