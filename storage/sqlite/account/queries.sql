-- name: GetRegion :one
SELECT * FROM account_regions WHERE partition = ? AND account = ? AND region = ?;

-- name: PutRegion :exec
INSERT INTO account_regions (partition, account, region, status, due)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (partition, account, region) DO UPDATE SET
    status = excluded.status,
    due = excluded.due;

-- name: GetContact :one
SELECT * FROM account_contacts WHERE partition = ? AND account = ?;

-- name: PutContact :exec
INSERT INTO account_contacts (partition, account, full_name, address_line1, city, postal_code, country_code, phone_number, address_line2, address_line3, state_or_region, district_or_county, company_name, website_url)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account) DO UPDATE SET
    full_name = excluded.full_name,
    address_line1 = excluded.address_line1,
    city = excluded.city,
    postal_code = excluded.postal_code,
    country_code = excluded.country_code,
    phone_number = excluded.phone_number,
    address_line2 = excluded.address_line2,
    address_line3 = excluded.address_line3,
    state_or_region = excluded.state_or_region,
    district_or_county = excluded.district_or_county,
    company_name = excluded.company_name,
    website_url = excluded.website_url;

-- name: GetAlternateContact :one
SELECT * FROM account_alternate_contacts WHERE partition = ? AND account = ? AND contact_type = ?;

-- name: PutAlternateContact :exec
INSERT INTO account_alternate_contacts (partition, account, contact_type, name, title, email_address, phone_number)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account, contact_type) DO UPDATE SET
    name = excluded.name,
    title = excluded.title,
    email_address = excluded.email_address,
    phone_number = excluded.phone_number;

-- name: GetPrimaryEmailUpdate :one
SELECT * FROM account_email_updates WHERE partition = ? AND account = ?;

-- name: PutPrimaryEmailUpdate :exec
INSERT INTO account_email_updates (partition, account, generation, email, otp, status, updated_at, expires_at, due, notice_pending)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (partition, account) DO UPDATE SET
    generation = excluded.generation,
    email = excluded.email,
    otp = excluded.otp,
    status = excluded.status,
    updated_at = excluded.updated_at,
    expires_at = excluded.expires_at,
    due = excluded.due,
    notice_pending = excluded.notice_pending;

-- name: ListPrimaryEmailUpdates :many
SELECT * FROM account_email_updates ORDER BY partition, account;

-- name: DeleteAlternateContact :exec
DELETE FROM account_alternate_contacts WHERE partition = ? AND account = ? AND contact_type = ?;
