WITH ranked AS (
    SELECT "aid",
           row_number() OVER (
               PARTITION BY "uid", "file_hash"
               ORDER BY ("rid" IS NOT NULL) DESC, "created_at" DESC, "aid"
           ) AS "position"
    FROM "analysis"
    WHERE "deleted_at" IS NULL AND "file_hash" IS NOT NULL
)
SELECT "analysis"."uid",
       "analysis"."file_hash",
       "analysis"."file_name",
       "analysis"."status",
       "analysis"."tools",
       "analysis"."task_id",
       "analysis"."rid",
       "analysis"."created_at",
       ranked."position",
       CASE WHEN ranked."position" = 1 THEN 'keep' ELSE 'hide' END AS "action"
FROM ranked
JOIN "analysis" ON "analysis"."aid" = ranked."aid"
ORDER BY "analysis"."uid", "analysis"."file_hash", ranked."position";

WITH ranked AS (
    SELECT "aid",
           row_number() OVER (
               PARTITION BY "uid", "file_hash"
               ORDER BY ("rid" IS NOT NULL) DESC, "created_at" DESC, "aid"
           ) AS "position"
    FROM "analysis"
    WHERE "deleted_at" IS NULL AND "file_hash" IS NOT NULL
)
UPDATE "analysis"
SET "deleted_at" = now()
WHERE "aid" IN (SELECT "aid" FROM ranked WHERE "position" > 1);

SELECT count(*) AS active_rows_after_cleanup
FROM "analysis"
WHERE "deleted_at" IS NULL;

SELECT count(*) AS duplicated_content_per_user
FROM (
    SELECT "uid", "file_hash"
    FROM "analysis"
    WHERE "deleted_at" IS NULL AND "file_hash" IS NOT NULL
    GROUP BY "uid", "file_hash"
    HAVING count(*) > 1
) AS duplicates;
