-- Account owns regional availability, contacts and primary-email jobs.
CREATE TABLE account_regions (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    region TEXT NOT NULL,
    status TEXT NOT NULL,
    due TIMESTAMP NOT NULL,
    PRIMARY KEY (partition, account, region)
);

CREATE TABLE account_contacts (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    full_name TEXT NOT NULL,
    address_line1 TEXT NOT NULL,
    city TEXT NOT NULL,
    postal_code TEXT NOT NULL,
    country_code TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    address_line2 TEXT NOT NULL,
    address_line3 TEXT NOT NULL,
    state_or_region TEXT NOT NULL,
    district_or_county TEXT NOT NULL,
    company_name TEXT NOT NULL,
    website_url TEXT NOT NULL,
    PRIMARY KEY (partition, account)
);

CREATE TABLE account_alternate_contacts (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    contact_type TEXT NOT NULL,
    name TEXT NOT NULL,
    title TEXT NOT NULL,
    email_address TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    PRIMARY KEY (partition, account, contact_type)
);

CREATE TABLE account_email_updates (
    partition TEXT NOT NULL,
    account TEXT NOT NULL,
    generation BLOB NOT NULL,
    email TEXT NOT NULL,
    otp TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    due TIMESTAMP NOT NULL,
    notice_pending BOOLEAN NOT NULL,
    PRIMARY KEY (partition, account)
);
