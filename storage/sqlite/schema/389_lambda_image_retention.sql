ALTER TABLE lambda_function_images ADD COLUMN pin_reference TEXT NOT NULL DEFAULT '';
ALTER TABLE lambda_function_images ADD COLUMN pin_lease TEXT NOT NULL DEFAULT '';
