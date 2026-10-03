-- name: GetGlueClassifier :one
SELECT * FROM glue_classifiers WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;
-- name: ListGlueClassifiers :many
SELECT * FROM glue_classifiers WHERE partition = ? AND account_id = ? AND region = ? ORDER BY name;
-- name: DeleteGlueClassifier :exec
DELETE FROM glue_classifiers WHERE partition = ? AND account_id = ? AND region = ? AND name = ?;
-- name: PutGlueClassifier :exec
INSERT INTO glue_classifiers (partition,account_id,region,name,kind,classification,grok_pattern,custom_patterns,json_path,row_tag,delimiter,quote_symbol,contains_header,header,allow_single_column,disable_value_trimming,custom_datatype_configured,custom_datatypes,serde,version,created_at,updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(partition,account_id,region,name) DO UPDATE SET classification=excluded.classification,grok_pattern=excluded.grok_pattern,custom_patterns=excluded.custom_patterns,json_path=excluded.json_path,row_tag=excluded.row_tag,delimiter=excluded.delimiter,quote_symbol=excluded.quote_symbol,contains_header=excluded.contains_header,header=excluded.header,allow_single_column=excluded.allow_single_column,disable_value_trimming=excluded.disable_value_trimming,custom_datatype_configured=excluded.custom_datatype_configured,custom_datatypes=excluded.custom_datatypes,serde=excluded.serde,version=excluded.version,updated_at=excluded.updated_at;
