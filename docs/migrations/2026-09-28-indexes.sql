CREATE INDEX IF NOT EXISTS "ix_oauth_accounts_uid" ON "oauth_accounts"("uid");
CREATE INDEX IF NOT EXISTS "ix_analysis_file_hash" ON "analysis"("file_hash");
CREATE INDEX IF NOT EXISTS "ix_analysis_task_id" ON "analysis"("task_id");
CREATE INDEX IF NOT EXISTS "ix_analysis_uid_created_at" ON "analysis"("uid", "created_at" DESC);
CREATE INDEX IF NOT EXISTS "ix_analysis_md5" ON "analysis"("md5");
CREATE INDEX IF NOT EXISTS "ix_analysis_created_at" ON "analysis"("created_at" DESC);

CREATE INDEX IF NOT EXISTS "ix_audit_logs_created_at" ON "audit_logs"("created_at" DESC);
CREATE INDEX IF NOT EXISTS "ix_audit_logs_actor_uid_created_at" ON "audit_logs"("actor_uid", "created_at" DESC);
CREATE INDEX IF NOT EXISTS "ix_login_history_uid_created_at" ON "login_history"("uid", "created_at" DESC);
CREATE INDEX IF NOT EXISTS "ix_download_history_uid_created_at" ON "download_history"("uid", "created_at" DESC);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON kcu.constraint_name = tc.constraint_name
         AND kcu.table_schema = tc.table_schema
        WHERE tc.table_schema = 'public'
          AND tc.table_name = 'oauth_accounts'
          AND tc.constraint_type = 'UNIQUE'
        GROUP BY tc.constraint_name
        HAVING array_agg(kcu.column_name::text ORDER BY kcu.column_name) = ARRAY['provider', 'provider_uid']
    ) THEN
        IF EXISTS (
            SELECT 1 FROM "oauth_accounts"
            GROUP BY "provider", "provider_uid"
            HAVING count(*) > 1
        ) THEN
            RAISE NOTICE 'skipped uq_oauth_accounts_provider_identity: duplicate provider/provider_uid rows exist';
        ELSE
            ALTER TABLE "oauth_accounts"
                ADD CONSTRAINT "uq_oauth_accounts_provider_identity" UNIQUE ("provider", "provider_uid");
        END IF;
    END IF;
END $$;

SELECT tablename, indexname
FROM pg_indexes
WHERE schemaname = 'public'
  AND tablename IN ('analysis', 'audit_logs', 'login_history', 'download_history', 'oauth_accounts')
ORDER BY tablename, indexname;

SELECT count(*) AS duplicated_oauth_identities
FROM (
    SELECT "provider", "provider_uid"
    FROM "oauth_accounts"
    GROUP BY "provider", "provider_uid"
    HAVING count(*) > 1
) AS duplicates;

SELECT (to_regclass('public.uq_oauth_accounts_provider_identity')) IS NOT NULL AS unique_constraint_present;
