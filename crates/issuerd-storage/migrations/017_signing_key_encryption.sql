-- Envelope encryption for signing keys at rest (SECURITY_REVIEW_PLAN.md, item 3).
--
-- Expand phase of an expand-and-contract: adds the ciphertext columns and
-- relaxes the plaintext column so new binaries can write rows that hold ONLY
-- ciphertext (private_der = NULL). Legacy plaintext rows keep working — new
-- binaries decrypt-on-read / re-encrypt-on-write. The contract phase
-- (DROP COLUMN private_der) ships in a later migration once all supported
-- versions write encrypted rows.
--
-- Mixed-version caveat: rows written by a KEK-enabled binary have
-- private_der = NULL, which a pre-encryption binary cannot decode. Enable
-- [crypto.key_encryption] only after every node runs the new version.

ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS private_der_enc BYTEA;
ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS kek_kid TEXT;
ALTER TABLE signing_keys ALTER COLUMN private_der DROP NOT NULL;
