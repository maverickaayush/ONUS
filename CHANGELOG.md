# Changelog

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

### Added
- `GET /api/scan/{id}/findings` now includes two optional fields per finding
  that were already computed internally but previously dropped before
  reaching the API response: `confidence` (`"confirmed" | "probable" |
  "unverified"`) and `verification_note` (string, present only on findings a
  verifier actually re-checked). Both are additive and optional - existing
  API consumers are unaffected. See `/docs` (FastAPI/Swagger) for the field
  descriptions, or `ARCHITECTURE.md`'s "Confidence Verification" section for
  the full semantics.
