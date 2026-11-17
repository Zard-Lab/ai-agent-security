-- Vulnerable: SECURITY DEFINER, name suggests secret material, never revoked.
CREATE OR REPLACE FUNCTION read_secret_logged(secret_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  result text;
BEGIN
  SELECT decrypted_secret INTO result FROM vault.decrypted_secrets WHERE id = secret_id;
  RETURN result;
END;
$$;

-- Safe: SECURITY DEFINER too, but EXECUTE is revoked from PUBLIC/anon/authenticated
-- and granted only to service_role.
CREATE OR REPLACE FUNCTION get_tenant_summary(tenant_id uuid)
RETURNS TABLE(tenant_name text, member_count int)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY SELECT t.name, count(m.id)::int FROM tenants t
    LEFT JOIN memberships m ON m.tenant_id = t.id
    WHERE t.id = tenant_id
    GROUP BY t.name;
END;
$$;

REVOKE EXECUTE ON FUNCTION get_tenant_summary(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION get_tenant_summary(uuid) TO service_role;
