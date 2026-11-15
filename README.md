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

## Signature inventory

`PdfSignatureInventoryReader` finds the signatures a document actually uses. It follows the catalog (`/Perms /DocMDP`) and the signature fields (`/V`) through the PDF structure, including object streams and incremental updates.

```php
use LibreSign\PdfSignatureValidator\Parser\PdfSignatureInventoryReader;

$inventory = (new PdfSignatureInventoryReader())->readFromString($pdfBinaryContent);
// or: $inventory = (new PdfSignatureInventoryReader())->readFromResource($resource);
```

The `SignatureInventory` it returns has:
- `isConclusive`: `false` when the structure could not be read. The other fields are then empty, so treat the document with your most restrictive rules.
- `activeSignatureCount`: signature dictionaries that a field or the catalog points to.
- `orphanedSignatureCount`: signature dictionaries that nothing points to. They have no effect.
- `docMdpPermission`: the most restrictive DocMDP `/P` among the active signatures (`DocMdpPermission`), or `null` when the document is not certified.

## Development

Use the CI workflows as the source of truth. For local execution, use the scripts declared in `composer.json`.

