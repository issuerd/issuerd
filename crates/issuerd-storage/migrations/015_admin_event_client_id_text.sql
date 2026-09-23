-- auth_client_id holds the public OAuth client_id string (e.g. "admin-cli"),
-- not the client's internal UUID — Keycloak parity for AdminEvent.authClientId.
-- Existing UUID values are preserved as their canonical text form.
ALTER TABLE admin_events ALTER COLUMN auth_client_id TYPE TEXT USING auth_client_id::text;
