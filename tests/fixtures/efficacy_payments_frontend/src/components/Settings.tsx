export function readConfig() {
  // Mistake: a client-inlined secret env var.
  const stripeSecret = import.meta.env.VITE_STRIPE_SECRET_KEY;
  // Safe: the anon key is meant to be public.
  const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;
  return { stripeSecret, supabaseAnonKey };
}
