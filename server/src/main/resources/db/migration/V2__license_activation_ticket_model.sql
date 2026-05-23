alter table licenses
    add column if not exists blocked boolean not null default false;

alter table licenses
    add column if not exists activated_at timestamp with time zone;

alter table licenses
    add column if not exists device_id varchar(128);

alter table licenses
    add column if not exists validity_days integer not null default 365;

update licenses
set active = false,
    blocked = false,
    activated_at = null,
    device_id = null,
    expires_at = null
where true;

create index if not exists idx_licenses_user_active on licenses(user_id, active);
create index if not exists idx_licenses_device_id on licenses(device_id);
