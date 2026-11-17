CREATE TABLE public.stripe_tokens (id uuid primary key, user_id uuid, balance int);
-- PLANTED: no ENABLE ROW LEVEL SECURITY on a public billing table
