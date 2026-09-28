-- FundLedger safe RPC upgrade migration.
-- These DROP FUNCTION statements remove only old stored-function definitions whose
-- return structure changed. They do not delete messages, users, contracts, payments,
-- analytics events, or any table data.

-- FundLedger / Supabase setup
-- Run this entire file in Supabase SQL Editor.
-- IMPORTANT: Before using the Admin Dashboard, set the intended admin user's
-- auth.users.raw_app_meta_data.role to 'admin' (instructions are at the bottom).

create extension if not exists pgcrypto;

-- ============================================================
-- 1. Per-user FundLedger data
-- ============================================================
create table if not exists public.contract_tracker_data (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{"contracts":[],"checks":[]}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.contract_tracker_data enable row level security;

drop policy if exists "Users can read own contract data" on public.contract_tracker_data;
drop policy if exists "Users can insert own contract data" on public.contract_tracker_data;
drop policy if exists "Users can update own contract data" on public.contract_tracker_data;

create policy "Users can read own contract data"
on public.contract_tracker_data for select
to authenticated
using (user_id = auth.uid());

create policy "Users can insert own contract data"
on public.contract_tracker_data for insert
to authenticated
with check (user_id = auth.uid());

create policy "Users can update own contract data"
on public.contract_tracker_data for update
to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());

-- ============================================================
-- 2. Account restrictions used by Admin Dashboard
-- ============================================================
create table if not exists public.account_restrictions (
  user_id uuid primary key references auth.users(id) on delete cascade,
  login_banned boolean not null default false,
  messages_blocked boolean not null default false,
  updated_at timestamptz not null default now()
);

alter table public.account_restrictions enable row level security;

-- Users do not receive direct table access. The app uses the RPCs below.
drop policy if exists "No direct account restriction access" on public.account_restrictions;

-- ============================================================
-- 3. Contact Us messages
-- ============================================================
create table if not exists public.contact_messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null default '',
  message text not null,
  admin_reply text,
  created_at timestamptz not null default now(),
  replied_at timestamptz,
  conversation_status text not null default 'new'
    check (conversation_status in ('new','ongoing','saved'))
);

alter table public.contact_messages enable row level security;

-- Direct RLS access for a user's own messages is allowed. Admin operations use RPCs.
drop policy if exists "Users can read own messages" on public.contact_messages;
drop policy if exists "Users can insert own messages" on public.contact_messages;

create policy "Users can read own messages"
on public.contact_messages for select
to authenticated
using (user_id = auth.uid());

create policy "Users can insert own messages"
on public.contact_messages for insert
to authenticated
with check (user_id = auth.uid());

-- ============================================================
-- 4. Helper: is current user an admin
-- ============================================================
create or replace function public.is_fundledger_admin()
returns boolean
language sql
stable
security definer
set search_path = public, auth
as $$
  select coalesce((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false);
$$;

revoke all on function public.is_fundledger_admin() from public;
grant execute on function public.is_fundledger_admin() to authenticated;

-- ============================================================
-- 5. User restrictions RPCs
-- ============================================================
create or replace function public.get_my_account_restrictions()
returns table(login_banned boolean, messages_blocked boolean)
language sql
stable
security definer
set search_path = public, auth
as $$
  select
    coalesce(r.login_banned, false),
    coalesce(r.messages_blocked, false)
  from (select auth.uid() as user_id) u
  left join public.account_restrictions r on r.user_id = u.user_id;
$$;

create or replace function public.admin_get_user_restrictions(p_user_id uuid)
returns table(login_banned boolean, messages_blocked boolean)
language sql
stable
security definer
set search_path = public, auth
as $$
  select
    coalesce(r.login_banned, false),
    coalesce(r.messages_blocked, false)
  from (select p_user_id as user_id) u
  left join public.account_restrictions r on r.user_id = u.user_id
  where public.is_fundledger_admin();
$$;

create or replace function public.admin_set_user_login_banned(p_user_id uuid, p_banned boolean)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not public.is_fundledger_admin() then
    raise exception 'Admin access required';
  end if;
  if p_user_id = auth.uid() then
    raise exception 'You cannot ban your own admin account';
  end if;
  insert into public.account_restrictions(user_id, login_banned, updated_at)
  values (p_user_id, p_banned, now())
  on conflict (user_id) do update
    set login_banned = excluded.login_banned,
        updated_at = now();
end;
$$;

create or replace function public.admin_set_user_messages_blocked(p_user_id uuid, p_blocked boolean)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not public.is_fundledger_admin() then
    raise exception 'Admin access required';
  end if;
  insert into public.account_restrictions(user_id, messages_blocked, updated_at)
  values (p_user_id, p_blocked, now())
  on conflict (user_id) do update
    set messages_blocked = excluded.messages_blocked,
        updated_at = now();
end;
$$;

-- ============================================================
-- 6. Admin user list + selected user's FundLedger data
-- ============================================================
create or replace function public.admin_list_users()
returns table(id uuid, email text, created_at timestamptz)
language sql
stable
security definer
set search_path = public, auth
as $$
  select u.id, u.email::text, u.created_at
  from auth.users u
  where public.is_fundledger_admin()
  order by lower(coalesce(u.email, ''));
$$;

create or replace function public.admin_get_user_data(target_user_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = public, auth
as $$
declare
  result jsonb;
begin
  if not public.is_fundledger_admin() then
    raise exception 'Admin access required';
  end if;

  select coalesce(c.data, '{"contracts":[],"checks":[]}'::jsonb)
    into result
  from public.contract_tracker_data c
  where c.user_id = target_user_id;

  return coalesce(result, '{"contracts":[],"checks":[]}'::jsonb);
end;
$$;

-- ============================================================
-- 7. Contact Us RPCs
-- ============================================================
drop function if exists public.contact_list_my_messages();
create or replace function public.contact_list_my_messages()
returns setof public.contact_messages
language sql
stable
security definer
set search_path = public, auth
as $$
  select * from public.contact_messages
  where user_id = auth.uid()
  order by created_at desc;
$$;

drop function if exists public.contact_admin_list_messages();
create or replace function public.contact_admin_list_messages()
returns setof public.contact_messages
language sql
stable
security definer
set search_path = public, auth
as $$
  select * from public.contact_messages
  where public.is_fundledger_admin()
  order by created_at desc;
$$;

create or replace function public.contact_admin_reply_message(p_id uuid, p_reply text)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not public.is_fundledger_admin() then
    raise exception 'Admin access required';
  end if;
  update public.contact_messages
     set admin_reply = nullif(trim(p_reply), ''),
         replied_at = case when nullif(trim(p_reply), '') is null then null else now() end,
         conversation_status = case when nullif(trim(p_reply), '') is null then conversation_status else 'ongoing' end
   where id = p_id;
end;
$$;

create or replace function public.contact_delete_message(p_id uuid)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  delete from public.contact_messages
   where id = p_id and user_id = auth.uid();
end;
$$;

create or replace function public.contact_admin_delete_message(p_id uuid)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not public.is_fundledger_admin() then
    raise exception 'Admin access required';
  end if;
  delete from public.contact_messages where id = p_id;
end;
$$;

create or replace function public.contact_admin_set_conversation_status(p_user_id uuid, p_status text)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not public.is_fundledger_admin() then
    raise exception 'Admin access required';
  end if;
  if p_status not in ('new','ongoing','saved') then
    raise exception 'Invalid conversation status';
  end if;
  update public.contact_messages
     set conversation_status = p_status
   where user_id = p_user_id;
end;
$$;

create or replace function public.contact_admin_delete_user_messages(p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not public.is_fundledger_admin() then
    raise exception 'Admin access required';
  end if;
  delete from public.contact_messages where user_id = p_user_id;
end;
$$;

create or replace function public.contact_delete_all_my_messages()
returns void
language sql
security definer
set search_path = public, auth
as $$
  delete from public.contact_messages where user_id = auth.uid();
$$;

create or replace function public.contact_admin_delete_all_messages()
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not public.is_fundledger_admin() then
    raise exception 'Admin access required';
  end if;
  delete from public.contact_messages;
end;
$$;

-- ============================================================
-- 8. Permissions for RPCs
-- ============================================================
revoke all on function public.get_my_account_restrictions() from public;
revoke all on function public.admin_get_user_restrictions(uuid) from public;
revoke all on function public.admin_set_user_login_banned(uuid,boolean) from public;
revoke all on function public.admin_set_user_messages_blocked(uuid,boolean) from public;
revoke all on function public.admin_list_users() from public;
revoke all on function public.admin_get_user_data(uuid) from public;
revoke all on function public.contact_list_my_messages() from public;
revoke all on function public.contact_admin_list_messages() from public;
revoke all on function public.contact_admin_reply_message(uuid,text) from public;
revoke all on function public.contact_delete_message(uuid) from public;
revoke all on function public.contact_admin_delete_message(uuid) from public;
revoke all on function public.contact_admin_set_conversation_status(uuid,text) from public;
revoke all on function public.contact_admin_delete_user_messages(uuid) from public;
revoke all on function public.contact_delete_all_my_messages() from public;
revoke all on function public.contact_admin_delete_all_messages() from public;

-- Authenticated users can execute the RPCs; each RPC performs its own authorization.
grant execute on function public.get_my_account_restrictions() to authenticated;
grant execute on function public.admin_get_user_restrictions(uuid) to authenticated;
grant execute on function public.admin_set_user_login_banned(uuid,boolean) to authenticated;
grant execute on function public.admin_set_user_messages_blocked(uuid,boolean) to authenticated;
grant execute on function public.admin_list_users() to authenticated;

grant execute on function public.contact_list_my_messages() to authenticated;
grant execute on function public.contact_admin_list_messages() to authenticated;
grant execute on function public.contact_admin_reply_message(uuid,text) to authenticated;
grant execute on function public.contact_delete_message(uuid) to authenticated;
grant execute on function public.contact_admin_delete_message(uuid) to authenticated;
grant execute on function public.contact_admin_set_conversation_status(uuid,text) to authenticated;
grant execute on function public.contact_admin_delete_user_messages(uuid) to authenticated;
grant execute on function public.contact_delete_all_my_messages() to authenticated;
grant execute on function public.contact_admin_delete_all_messages() to authenticated;

-- ============================================================
-- 9. OPTIONAL: make an existing Auth user an admin
-- ============================================================
-- Replace the email below with the account that should be the MASTER ADMIN.
-- Run this separately after the main setup above if needed.
--
-- update auth.users
-- set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{"role":"admin"}'::jsonb
-- where email = 'YOUR-ADMIN-EMAIL@example.com';
--
-- The user should then sign out and sign back in so the new JWT contains role=admin.


-- FundLedger traffic and user analytics
create table if not exists public.fundledger_analytics_events (
  id bigint generated by default as identity primary key,
  event_type text not null check (event_type in ('visit','login','active','signup')),
  visitor_id text,
  user_id uuid references auth.users(id) on delete set null,
  path text,
  created_at timestamptz not null default now()
);
create index if not exists fundledger_analytics_events_created_idx on public.fundledger_analytics_events(created_at);
create index if not exists fundledger_analytics_events_user_idx on public.fundledger_analytics_events(user_id);
alter table public.fundledger_analytics_events enable row level security;

create or replace function public.track_fundledger_event(p_event_type text,p_visitor_id text default null,p_path text default '/')
returns void language plpgsql security definer set search_path=public as $$
begin
 if p_event_type not in ('visit','login','active','signup') then return; end if;
 insert into public.fundledger_analytics_events(event_type,visitor_id,user_id,path)
 values(p_event_type,left(coalesce(p_visitor_id,''),100),auth.uid(),left(coalesce(p_path,'/'),300));
end $$;
grant execute on function public.track_fundledger_event(text,text,text) to anon,authenticated;

create or replace function public.admin_fundledger_analytics(p_period text default '30')
returns jsonb language plpgsql security definer set search_path=public,auth as $$
declare
 days_n int; start_now timestamptz; start_prev timestamptz; end_prev timestamptz; result jsonb;
begin
 if not exists(select 1 from auth.users u where u.id=auth.uid() and lower(coalesce(u.email,''))='info@fundledger.app') then
   raise exception 'Admin only';
 end if;
 days_n:=case when p_period='7' then 7 when p_period='year' then 365 when p_period='month' then greatest(1,extract(day from now())::int) else 30 end;
 start_now:=now()-(days_n||' days')::interval; end_prev:=start_now; start_prev:=start_now-(days_n||' days')::interval;
 select jsonb_build_object(
  'current',jsonb_build_object(
   'visitors',(select count(distinct visitor_id) from public.fundledger_analytics_events where created_at>=start_now and event_type='visit'),
   'visits',(select count(*) from public.fundledger_analytics_events where created_at>=start_now and event_type='visit'),
   'users',(select count(*) from auth.users),
   'active',(select count(distinct user_id) from public.fundledger_analytics_events where created_at>=start_now and user_id is not null and event_type in ('active','login')),
   'logins',(select count(*) from public.fundledger_analytics_events where created_at>=start_now and event_type='login'),
   'new_accounts',(select count(*) from auth.users where created_at>=start_now)),
  'previous',jsonb_build_object(
   'visitors',(select count(distinct visitor_id) from public.fundledger_analytics_events where created_at>=start_prev and created_at<end_prev and event_type='visit'),
   'visits',(select count(*) from public.fundledger_analytics_events where created_at>=start_prev and created_at<end_prev and event_type='visit'),
   'users',(select count(*) from auth.users where created_at<end_prev),
   'active',(select count(distinct user_id) from public.fundledger_analytics_events where created_at>=start_prev and created_at<end_prev and user_id is not null and event_type in ('active','login')),
   'logins',(select count(*) from public.fundledger_analytics_events where created_at>=start_prev and created_at<end_prev and event_type='login'),
   'new_accounts',(select count(*) from auth.users where created_at>=start_prev and created_at<end_prev)),
  'trend',(select coalesce(jsonb_agg(x order by x.trend_day),'[]'::jsonb) from (select to_char(created_at::date,'Mon DD') as trend_day,count(*) as visits from public.fundledger_analytics_events where created_at>=start_now and event_type='visit' group by created_at::date) x),
  'user_activity',(select coalesce(jsonb_agg(x order by x.last_active desc nulls last),'[]'::jsonb) from (
    select u.email,u.created_at,max(e.created_at) filter(where e.event_type='login') last_login,
      count(e.id) filter(where e.event_type='login') login_count,max(e.created_at) last_active,
      (max(e.created_at)>=now()-interval '7 days') active
    from auth.users u left join public.fundledger_analytics_events e on e.user_id=u.id group by u.id,u.email,u.created_at limit 250) x)
 ) into result;
 return result;
end $$;
grant execute on function public.admin_fundledger_analytics(text) to authenticated;


-- FundLedger privacy hardening for App Store/mobile distribution.
-- Administrators may see aggregate analytics, but cannot retrieve another user's
-- contracts, checks/payments, or private FundLedger account contents.
revoke execute on function public.admin_get_user_data(uuid) from authenticated;
revoke execute on function public.admin_get_user_data(uuid) from anon;

create or replace function public.admin_get_user_data(target_user_id uuid)
returns jsonb language plpgsql security definer set search_path=public as $$
begin
  raise exception 'Cross-user financial data access is disabled for privacy.';
end $$;
revoke all on function public.admin_get_user_data(uuid) from public;
revoke all on function public.admin_get_user_data(uuid) from authenticated;
revoke all on function public.admin_get_user_data(uuid) from anon;


-- FundLedger per-user encryption key recovery.
-- Each authenticated user can access only their own recovery key row.
create table if not exists public.fundledger_user_keys (
  user_id uuid primary key references auth.users(id) on delete cascade,
  wrapped_key text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.fundledger_user_keys enable row level security;

drop policy if exists "fundledger_keys_select_own" on public.fundledger_user_keys;
create policy "fundledger_keys_select_own" on public.fundledger_user_keys
for select to authenticated using (auth.uid() = user_id);

drop policy if exists "fundledger_keys_insert_own" on public.fundledger_user_keys;
create policy "fundledger_keys_insert_own" on public.fundledger_user_keys
for insert to authenticated with check (auth.uid() = user_id);

drop policy if exists "fundledger_keys_update_own" on public.fundledger_user_keys;
create policy "fundledger_keys_update_own" on public.fundledger_user_keys
for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);

revoke all on table public.fundledger_user_keys from anon;
grant select,insert,update on table public.fundledger_user_keys to authenticated;


-- FundLedger Realtime device synchronization.
-- RLS remains authoritative: each authenticated user receives only their own row.
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname='supabase_realtime'
      and schemaname='public'
      and tablename='contract_tracker_data'
  ) then
    alter publication supabase_realtime add table public.contract_tracker_data;
  end if;
end $$;

-- ============================================================
-- FundLedger Free / Pro plans
-- Free: ads, up to 3 active contracts, no Reports.
-- Pro: $9.99/month entitlement, unlimited active contracts, Reports, no ads.
-- Billing provider/webhook should update plan='pro' only after verified payment.
-- ============================================================
create table if not exists public.fundledger_subscriptions (
  user_id uuid primary key references auth.users(id) on delete cascade,
  plan text not null default 'free' check (plan in ('free','pro')),
  status text not null default 'active',
  provider text,
  provider_customer_id text,
  provider_subscription_id text,
  current_period_end timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.fundledger_subscriptions enable row level security;
drop policy if exists "subscription_read_own" on public.fundledger_subscriptions;
create policy "subscription_read_own" on public.fundledger_subscriptions for select to authenticated using (auth.uid()=user_id);
revoke all on table public.fundledger_subscriptions from anon;
grant select on table public.fundledger_subscriptions to authenticated;

create or replace function public.get_my_fundledger_plan()
returns text language sql stable security definer set search_path=public as $$
 select case when exists(
   select 1 from public.fundledger_subscriptions s
   where s.user_id=auth.uid() and s.plan='pro' and s.status in ('active','trialing')
   and (s.current_period_end is null or s.current_period_end>now())
 ) then 'pro' else 'free' end;
$$;
revoke all on function public.get_my_fundledger_plan() from public;
grant execute on function public.get_my_fundledger_plan() to authenticated;

-- Backfill a Free-plan row for existing users. New users can safely remain implicit Free
-- until your verified billing webhook creates/updates their subscription row.
insert into public.fundledger_subscriptions(user_id,plan,status)
select id,'free','active' from auth.users
on conflict (user_id) do nothing;

-- Analytics now includes plan counts directly from Auth + subscriptions.
create or replace function public.admin_fundledger_analytics(p_period text default '30')
returns jsonb language plpgsql security definer set search_path=public,auth as $$
declare days_n int; start_now timestamptz; start_prev timestamptz; end_prev timestamptz; result jsonb;
begin
 if not exists(select 1 from auth.users u where u.id=auth.uid() and lower(coalesce(u.email,''))='info@fundledger.app') then raise exception 'Admin only'; end if;
 days_n:=case when p_period='7' then 7 when p_period='year' then 365 when p_period='month' then greatest(1,extract(day from now())::int) else 30 end;
 start_now:=now()-(days_n||' days')::interval; end_prev:=start_now; start_prev:=start_now-(days_n||' days')::interval;
 select jsonb_build_object(
  'current',jsonb_build_object(
   'visitors',(select count(distinct visitor_id) from public.fundledger_analytics_events where created_at>=start_now and event_type='visit'),
   'visits',(select count(*) from public.fundledger_analytics_events where created_at>=start_now and event_type='visit'),
   'users',(select count(*) from auth.users),
   'active',(select count(distinct user_id) from public.fundledger_analytics_events where created_at>=start_now and user_id is not null and event_type in ('active','login')),
   'logins',(select count(*) from public.fundledger_analytics_events where created_at>=start_now and event_type='login'),
   'new_accounts',(select count(*) from auth.users where created_at>=start_now),
   'paid_subscribers',(select count(*) from public.fundledger_subscriptions where plan='pro' and status in ('active','trialing') and (current_period_end is null or current_period_end>now())),
   'free_subscribers',(select count(*) from auth.users u where not exists(select 1 from public.fundledger_subscriptions s where s.user_id=u.id and s.plan='pro' and s.status in ('active','trialing') and (s.current_period_end is null or s.current_period_end>now()))),
   'trial_subscribers',(select count(*) from public.fundledger_subscriptions where status='trialing')),
  'previous',jsonb_build_object(
   'visitors',(select count(distinct visitor_id) from public.fundledger_analytics_events where created_at>=start_prev and created_at<end_prev and event_type='visit'),
   'visits',(select count(*) from public.fundledger_analytics_events where created_at>=start_prev and created_at<end_prev and event_type='visit'),
   'users',(select count(*) from auth.users where created_at<end_prev),
   'active',(select count(distinct user_id) from public.fundledger_analytics_events where created_at>=start_prev and created_at<end_prev and user_id is not null and event_type in ('active','login')),
   'logins',(select count(*) from public.fundledger_analytics_events where created_at>=start_prev and created_at<end_prev and event_type='login'),
   'new_accounts',(select count(*) from auth.users where created_at>=start_prev and created_at<end_prev)),
  'trend',(select coalesce(jsonb_agg(x order by x.trend_day),'[]'::jsonb) from (select to_char(created_at::date,'Mon DD') trend_day,count(*) visits from public.fundledger_analytics_events where created_at>=start_now and event_type='visit' group by created_at::date) x),
  'user_activity',(select coalesce(jsonb_agg(x order by x.last_active desc nulls last),'[]'::jsonb) from (select u.email,u.created_at,max(e.created_at) filter(where e.event_type='login') last_login,count(e.id) filter(where e.event_type='login') login_count,max(e.created_at) last_active,(max(e.created_at)>=now()-interval '7 days') active from auth.users u left join public.fundledger_analytics_events e on e.user_id=u.id group by u.id,u.email,u.created_at limit 250) x)
 ) into result; return result;
end $$;
grant execute on function public.admin_fundledger_analytics(text) to authenticated;


-- ============================================================
-- Admin-managed Pro access: custom trials + complimentary access
-- Safe: changes entitlement rows only; never touches contract/payment data.
-- ============================================================
create or replace function public.admin_set_fundledger_access(
  p_email text,
  p_access text,
  p_trial_end timestamptz default null
) returns jsonb
language plpgsql security definer set search_path=public,auth as $$
declare v_user uuid; v_email text; v_access text:=lower(trim(coalesce(p_access,'')));
begin
  if not public.is_fundledger_admin() then raise exception 'Admin access required'; end if;
  select id,email into v_user,v_email from auth.users where lower(email)=lower(trim(p_email)) limit 1;
  if v_user is null then raise exception 'No FundLedger account found for that email'; end if;
  if v_access='trial' then
    if p_trial_end is null or p_trial_end<=now() then raise exception 'Choose a future trial end date'; end if;
    insert into public.fundledger_subscriptions(user_id,plan,status,provider,current_period_end,updated_at)
    values(v_user,'pro','trialing','admin_trial',p_trial_end,now())
    on conflict(user_id) do update set plan='pro',status='trialing',provider='admin_trial',provider_customer_id=null,provider_subscription_id=null,current_period_end=excluded.current_period_end,updated_at=now();
  elsif v_access='complimentary' then
    insert into public.fundledger_subscriptions(user_id,plan,status,provider,current_period_end,updated_at)
    values(v_user,'pro','active','admin_complimentary',null,now())
    on conflict(user_id) do update set plan='pro',status='active',provider='admin_complimentary',provider_customer_id=null,provider_subscription_id=null,current_period_end=null,updated_at=now();
  elsif v_access='free' then
    insert into public.fundledger_subscriptions(user_id,plan,status,provider,current_period_end,updated_at)
    values(v_user,'free','active','admin',null,now())
    on conflict(user_id) do update set plan='free',status='active',provider='admin',provider_customer_id=null,provider_subscription_id=null,current_period_end=null,updated_at=now();
  else raise exception 'Access must be trial, complimentary, or free'; end if;
  return jsonb_build_object('ok',true,'email',v_email,'access',v_access,'trial_end',p_trial_end);
end $$;
revoke all on function public.admin_set_fundledger_access(text,text,timestamptz) from public;
grant execute on function public.admin_set_fundledger_access(text,text,timestamptz) to authenticated;

create or replace function public.admin_get_fundledger_access(p_email text)
returns jsonb language plpgsql security definer set search_path=public,auth as $$
declare v_user uuid; v_email text; v_row public.fundledger_subscriptions%rowtype;
begin
 if not public.is_fundledger_admin() then raise exception 'Admin access required'; end if;
 select id,email into v_user,v_email from auth.users where lower(email)=lower(trim(p_email)) limit 1;
 if v_user is null then raise exception 'No FundLedger account found for that email'; end if;
 select * into v_row from public.fundledger_subscriptions where user_id=v_user;
 return jsonb_build_object('email',v_email,'plan',coalesce(v_row.plan,'free'),'status',coalesce(v_row.status,'active'),'provider',v_row.provider,'current_period_end',v_row.current_period_end);
end $$;
revoke all on function public.admin_get_fundledger_access(text) from public;
grant execute on function public.admin_get_fundledger_access(text) to authenticated;


-- ============================================================
-- Self-service account deletion
-- Deletes only the currently authenticated user. Existing ON DELETE CASCADE
-- relationships remove that user's FundLedger rows with the auth account.
-- ============================================================
create or replace function public.delete_my_fundledger_account()
returns void language plpgsql security definer set search_path=public,auth as $$
declare v_uid uuid:=auth.uid();
begin
  if v_uid is null then raise exception 'Not signed in'; end if;
  delete from auth.users where id=v_uid;
end $$;
revoke all on function public.delete_my_fundledger_account() from public;
grant execute on function public.delete_my_fundledger_account() to authenticated;
