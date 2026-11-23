<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# DocMDP validation-data revision audit

**Status:** design reference for [PR #90](https://github.com/LibreSign/pdf-signature-validator/pull/90), not a declaration of complete interoperability.

## Responsibility boundary

This library, rather than the LibreSign Nextcloud application, owns the question:
**does every incremental PDF revision after the certifying signature contain
only structurally admissible DSS and document-timestamp updates?**

This is deliberately narrower than a complete PDF signature validation verdict.
A structurally allowed update does **not** establish that the RFC 3161 token,
CMS signature, trust chain, certificate or OCSP/CRL response is authentic.

The caller supplies the end of the **certifying signature's ByteRange**. The
inspection result is a boolean exemption predicate; `false` means *not proven
to be validation-data-only*, not automatically *cryptographically invalid*.
Normal DocMDP signature validation must still run.

## Directory structure and dependency direction

```text
src/
  Pdf/
    Syntax/
      PdfSyntaxReader.php
      PdfLiteralStringReader.php
    Revision/
      PdfCrossReferenceReader.php
      PdfIncrementalRevisionReader.php
      PdfRevisionSnapshot.php
  Validation/
    DocMdp/
      DocMdpValidationDataInspector.php
      Model/
        DocMdpRevisionState.php
      Policy/
        DocMdpValidationDataPolicy.php
        DocMdpRevisionPolicy.php
        DocMdpEntryChangePolicy.php
        DocMdpNewObjectPolicy.php
        DssChangeRule.php
        DocumentTimestampRule.php
```

- `Pdf/Syntax` reads and canonicalizes PDF values without deciding whether
  a modification is authorized.
- `Pdf/Revision` reads historical cross-reference tables and the distinct
  incremental revisions. It **fails closed** on unsupported structures.
- `Validation/DocMdp/Policy` evaluates object changes and grants a limited
  DSS/document-timestamp exception.
- `Validation/DocMdp/Model` holds state local to one evaluation.
- The public inspector is a thin facade; applications do not invoke the parser
  or policy classes directly.

These namespace boundaries intentionally do not relocate unrelated, existing
classes from `src/Parser`. Those classes require a separately reviewed migration.

## Comparison with free implementations (source-level architectural review)

| Implementation | How it handles revisions / security | Lesson for this PR |
| --- | --- | --- |
| pyHanko (Python) | `diff_analysis.StandardDiffPolicy` applies independently qualified whitelist rules; `DSSCompareRule` checks security-store changes, `SigFieldCreationRule` handles signature-field creation, and `XrefStreamRule` handles supported xref streams. The result distinguishes `LTA_UPDATES` from form filling and other changes. | Keep DSS, timestamp, object-change and revision-history responsibilities separate. Do **not** blindly whitelist every catalog change. |
| EU DSS (Java) | Its PDF differences finder identifies extension, signature/form, annotation and undefined changes; DocMDP and FieldMDP constraints evaluate them. | Separating the *description of changes* from their *legal admissibility* is useful for future diagnostic results; do not return a misleading cryptographic verdict from a structural predicate. |
| iText (Java, AGPL) | `DocumentRevisionsValidator` evaluates all revisions under DocMDP/FieldMDP permissions and reports unexpected xref changes. | Verify every intermediate revision, not only the final catalog. Structured reports are a future enhancement, not necessary for this narrow predicate. |
| Signet PDF (PHP, MIT) | `Validation/RevisionAnalyzer` produces `Data/RevisionDiff`, consumed by `Validation/CertificationEvaluator`. Its source explicitly notes that its current analyzer scans object definitions without fully resolving the historical object graph. | Its clean separation of facts from policy is useful; raw key/regex scanning alone is **not** a sufficient security decision for this PR. |
| SAPP (PHP, LGPL-3.0-or-later) | A PDF parser supporting incremental versions and xref streams, with signing capabilities. | Useful as an independent producer/parser, but its advertised feature set does not establish DocMDP DSS-approval semantics. |
| Apache PDFBox (Java, Apache-2.0) | Parses PDF and exposes signatures; its own FAQ says the ShowSignature example does not verify permitted or forbidden changes after signing. | Use it as a format interoperability reference, **not** the DocMDP acceptance oracle. |
| SignerPHP/pdf-core (PHP, MIT; existing dependency) | Provides parsing, xref/object-stream support, and revision information, including recovery behavior for malformed files. It does **not** currently expose the strict, per-revision security-diff contract needed by this inspector. | Avoid equating a recoverable structural parse with proof that an update is safe. Do not duplicate generic parsing indefinitely: consolidate only after a reviewed strict historical API becomes available. |

The comparison is based on published implementations and APIs, **not** a
completed pass/fail run of the same corpus against all products.

### Source references

- pyHanko: [diff policies](https://github.com/MatthiasValvekens/pyHanko/blob/master/pkgs/pyhanko/src/pyhanko/sign/diff_analysis/policies.py) and [DSS/field rules](https://github.com/MatthiasValvekens/pyHanko/blob/master/pkgs/pyhanko/src/pyhanko/sign/diff_analysis/rules/form_field_rules.py).
- EU DSS: [object modification detection and DocMDP constraints](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html).
- iText: [DocumentRevisionsValidator.java](https://github.com/itext/itext-java/blob/develop/sign/src/main/java/com/itextpdf/signatures/validation/DocumentRevisionsValidator.java).
- Signet: [RevisionAnalyzer.php](https://github.com/lsnepomuceno/signet-pdf/blob/main/src/Validation/RevisionAnalyzer.php), [CertificationEvaluator.php](https://github.com/lsnepomuceno/signet-pdf/blob/main/src/Validation/CertificationEvaluator.php).
- SAPP: [repository](https://github.com/dealfonso/sapp).
- PDFBox: [signature validation FAQ](https://pdfbox.apache.org/3.0/faq.html).
- SignerPHP: [pdf-core repository](https://github.com/SignerPHP/pdf-core).

## Security properties and negative controls

1. Preserve **each** incremental revision; never merge repeated definitions and
   compare only the final object. A temporary forbidden rewrite that is later
   restored must be rejected.
2. Do not accept new DSS references before their objects exist or timestamp
   fields that point to timestamp objects created in future revisions.
3. Restrict pre-certification object rewrites to whitelisted catalog, AcroForm
   and page-annotation changes associated with valid timestamp fields.
4. Reject unexpected object types, action dictionaries and modified content
   streams, metadata-only pretexts, duplicate xref definitions and malformed
   security-sensitive syntax.
5. Treat unsupported xref streams as **not proven**, not as accepted, and do
   not silently let a forgiving general-purpose PDF parser recover them.
6. Do not infer RFC 3161 token validity or OCSP/CRL trust from the existence
   of `/Type /DocTimeStamp` or `/DSS` keys.

## Conformance matrix still required before release

For each test PDF, separately record: **structural allowance** by this
library, **DocMDP modification status** from pyHanko/EU DSS/iText (where
available), and **cryptographic/trust status**. Those are not interchangeable.

| Corpus example | Structural expectation |
| --- | --- |
| P=1/2/3 certified file + genuine post-signature DSS only | Allowed |
| Certified file + genuine invisible document timestamp | Allowed |
| Timestamp followed by DSS, and DSS followed by timestamp | Allowed |
| DSS plus unrelated page, action, form or content modification | Rejected |
| Forbidden intermediate revision restored in a later revision | Rejected |
| Timestamp field points into a future revision | Rejected |
| Missing/incorrect DSS reference, duplicate xref entries | Rejected |
| Valid xref-stream-based signed PDF | **Unsupported by current strict reader**; must not be reported as allowed |
| Empty, malformed or incorrectly linked DSS substructures | Requires further format-specific conformance checks |

Existing unit tests include synthetic cases and a real certified PDF fixture
with a *locally constructed incremental DSS update*. Certificate evidence
is represented by PDF stream objects, as expected by the DSS data model.
The DSS rule checks that /Certs, /CRLs and /OCSPs are arrays of references
to streams introduced no later than the relevant revision. VRI subtree
validation remains incomplete and must not be claimed as full parity. This does **not**
constitute interoperability evidence for real pyHanko DSS output. In
particular, pyHanko performs richer DSS subtree checks than the current
`DssChangeRule`, whose check is intentionally limited to structural
identification of a newly referenced DSS dictionary.

**Release gate:** obtain real producer-generated PAdES/LT/LTA fixtures,
including xref-stream variants, compare results with pyHanko and EU DSS, and
obtain independent security review. If strict support for xref streams must
be added, first evaluate extending the existing `signerphp/pdf-core` contract
instead of adding a second permissive parser here.
