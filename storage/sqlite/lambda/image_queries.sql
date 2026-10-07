-- name: GetFunctionImage :one
SELECT * FROM lambda_function_images WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
-- name: DeleteFunctionImage :exec
DELETE FROM lambda_function_images WHERE partition=? AND account=? AND region=? AND function_name=? AND pending=? AND version=?;
-- name: PutFunctionImage :exec
INSERT INTO lambda_function_images(partition,account,region,function_name,pending,version,image_uri,image_id,resolved_image_uri,image_size,entrypoint,command,environment,working_directory,image_config,pin_reference,pin_lease,pin_image_id)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(partition,account,region,function_name,pending,version) DO UPDATE SET image_uri=excluded.image_uri,image_id=excluded.image_id,resolved_image_uri=excluded.resolved_image_uri,image_size=excluded.image_size,entrypoint=excluded.entrypoint,command=excluded.command,environment=excluded.environment,working_directory=excluded.working_directory,image_config=excluded.image_config,pin_reference=excluded.pin_reference,pin_lease=excluded.pin_lease,pin_image_id=excluded.pin_image_id;
