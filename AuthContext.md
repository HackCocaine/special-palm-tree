#FIRST TABLE


create table public.dashboards (
  id text primary key,              -- dashboard_id lógico (slug o uuid)
  payload jsonb not null,            -- dashboard completo
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);


#POLICIES FOR FIRST TABLE

alter table public.dashboard_access
enable row level security;


create policy "Users can read their own dashboard access"
on public.dashboard_access
for select
to authenticated
using (
  auth.uid() = user_id
  and (expires_at is null or expires_at > now())
);




create policy "No direct inserts from client"
on public.dashboard_access
for insert
to authenticated
with check (false);



SECOND TABLE

create table public.dashboard_access (
  user_id uuid not null,
  dashboard_id text not null,
  expires_at timestamptz,
  primary key (user_id, dashboard_id),
  foreign key (dashboard_id) references dashboards(id)
);


POLICIES FOR SECOND TABLE

alter table public.dashboards
enable row level security;


create policy "Users can read accessible dashboards"
on public.dashboards
for select
to authenticated
using (
  id in (
    select dashboard_id from dashboard_access 
    where user_id = auth.uid()                                                                 
    and (expires_at is null or expires_at > now())                                             
  )
);
