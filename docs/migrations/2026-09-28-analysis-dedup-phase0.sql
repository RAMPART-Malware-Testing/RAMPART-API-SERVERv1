ALTER TABLE "analysis" ADD COLUMN IF NOT EXISTS "tool_states" JSONB;

WITH ranked AS (
    SELECT "aid",
           row_number() OVER (
               PARTITION BY "task_id", "uid"
               ORDER BY ("rid" IS NOT NULL) DESC, "created_at" DESC, "aid"
           ) AS "position"
    FROM "analysis"
    WHERE "deleted_at" IS NULL AND "task_id" IS NOT NULL
)
UPDATE "analysis"
SET "deleted_at" = now()
WHERE "aid" IN (SELECT "aid" FROM ranked WHERE "position" > 1);

CREATE UNIQUE INDEX IF NOT EXISTS "uq_analysis_task_uid_active"
    ON "analysis" ("task_id", "uid") WHERE "deleted_at" IS NULL;

SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'analysis' AND indexname = 'uq_analysis_task_uid_active';

SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_name = 'analysis' AND column_name IN ('tool_notes', 'tool_states')
ORDER BY column_name;

SELECT count(*) AS still_duplicated
FROM (
    SELECT "task_id", "uid"
    FROM "analysis"
    WHERE "deleted_at" IS NULL AND "task_id" IS NOT NULL
    GROUP BY "task_id", "uid"
    HAVING count(*) > 1
) AS duplicates;
