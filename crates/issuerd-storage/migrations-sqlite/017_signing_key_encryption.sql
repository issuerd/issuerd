ALTER TABLE signing_keys ADD COLUMN private_der_enc BLOB;
ALTER TABLE signing_keys ADD COLUMN kek_kid TEXT;
