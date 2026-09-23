-- Realm OTP (TOTP) policy. The algorithm column stores the
-- Keycloak wire spelling ('HmacSHA1' | 'HmacSHA256' | 'HmacSHA512') so the
-- database value round-trips 1:1 with the admin API representation.
ALTER TABLE realms ADD COLUMN IF NOT EXISTS otp_algorithm TEXT NOT NULL DEFAULT 'HmacSHA1';
ALTER TABLE realms ADD COLUMN IF NOT EXISTS otp_digits INTEGER NOT NULL DEFAULT 6;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS otp_period_secs INTEGER NOT NULL DEFAULT 30;
ALTER TABLE realms ADD COLUMN IF NOT EXISTS otp_look_ahead_window INTEGER NOT NULL DEFAULT 1;
