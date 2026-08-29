import { createClient } from '@supabase/supabase-js';

export function getSupabaseConfig() {
  return {
    url: process.env.SUPABASE_URL || '',
    anonKey: process.env.SUPABASE_ANON_KEY || '',
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY || '',
  };
}

export function hasSupabaseConfig() {
  const { url, anonKey } = getSupabaseConfig();
  return Boolean(url && anonKey);
}

export function createSupabaseClient(useServiceRole = false) {
  const { url, anonKey, serviceRoleKey } = getSupabaseConfig();
  const key = useServiceRole ? serviceRoleKey || anonKey : anonKey;

  if (!url || !key) {
    return null;
  }

  return createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });
}

export function getSupabaseSetupError() {
  return 'Supabase is not configured. Add SUPABASE_URL and SUPABASE_ANON_KEY to your Vercel environment variables.';
}
