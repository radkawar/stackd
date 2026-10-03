package ec2

import (
	"database/sql"

	api "stackd/internal/awsapi/ec2"
	domain "stackd/storage/ec2"
	"stackd/storage/sqlite/ec2/internal/sqlcgen"
)

func (r reader) imageChildren(row sqlcgen.Ec2Image, out *domain.ImageRecord) error {
	k := out.Key
	if row.TagsPresent {
		tags, err := r.q.ListImageTags(r.ctx, sqlcgen.ListImageTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.Tags = make(api.TagList, len(tags))
		for i, tag := range tags {
			out.Data.Tags[i] = api.Tag{Key: stringPointer[api.String](tag.Key), Value: stringPointer[api.String](tag.Value)}
		}
	}
	if row.PermissionsPresent {
		permissions, err := r.q.ListImagePermissions(r.ctx, sqlcgen.ListImagePermissionsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.LaunchPermissions = make(api.LaunchPermissionList, len(permissions))
		for i, permission := range permissions {
			out.LaunchPermissions[i] = api.LaunchPermission{UserId: stringPointer[api.String](permission.UserID), Group: stringPointer[api.PermissionGroup](permission.PermissionGroup), OrganizationArn: stringPointer[api.String](permission.OrganizationArn), OrganizationalUnitArn: stringPointer[api.String](permission.OrganizationalUnitArn)}
		}
	}
	if row.ProductsPresent {
		products, err := r.q.ListImageProducts(r.ctx, sqlcgen.ListImageProductsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.ProductCodes = make(api.ProductCodeList, len(products))
		for i, product := range products {
			out.Data.ProductCodes[i] = api.ProductCode{ProductCodeId: stringPointer[api.String](product.ProductCodeID), ProductCodeType: stringPointer[api.ProductCodeValues](product.ProductCodeType)}
		}
	}
	if row.WatermarksPresent {
		watermarks, err := r.q.ListImageWatermarks(r.ctx, sqlcgen.ListImageWatermarksParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID})
		if err != nil {
			return err
		}
		out.Data.ImageWatermarks = make(api.ImageWatermarkList, len(watermarks))
		for i, watermark := range watermarks {
			out.Data.ImageWatermarks[i] = api.ImageWatermark{SourceImageId: stringPointer[api.String](watermark.SourceImageID), SourceImageRegion: stringPointer[api.String](watermark.SourceImageRegion), WatermarkKey: stringPointer[api.String](watermark.WatermarkKey)}
			if watermark.SourceImageCreationTime.Valid {
				out.Data.ImageWatermarks[i].SourceImageCreationTime = new(api.MillisecondDateTime(watermark.SourceImageCreationTime.Time))
			}
			if watermark.WatermarkCreationTime.Valid {
				out.Data.ImageWatermarks[i].WatermarkCreationTime = new(api.MillisecondDateTime(watermark.WatermarkCreationTime.Time))
			}
		}
	}
	return nil
}

func (w writer) putImageChildren(v domain.ImageRecord) error {
	k, d := v.Key, &v.Data
	if err := w.q.DeleteImageTags(w.ctx, sqlcgen.DeleteImageTagsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, tag := range d.Tags {
		if err := w.q.PutImageTag(w.ctx, sqlcgen.PutImageTagParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), Key: nullableString(tag.Key), Value: nullableString(tag.Value)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteImagePermissions(w.ctx, sqlcgen.DeleteImagePermissionsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, permission := range v.LaunchPermissions {
		if err := w.q.PutImagePermission(w.ctx, sqlcgen.PutImagePermissionParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), UserID: nullableString(permission.UserId), PermissionGroup: nullableString(permission.Group), OrganizationArn: nullableString(permission.OrganizationArn), OrganizationalUnitArn: nullableString(permission.OrganizationalUnitArn)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteImageProducts(w.ctx, sqlcgen.DeleteImageProductsParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, product := range d.ProductCodes {
		if err := w.q.PutImageProduct(w.ctx, sqlcgen.PutImageProductParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), ProductCodeID: nullableString(product.ProductCodeId), ProductCodeType: nullableString(product.ProductCodeType)}); err != nil {
			return err
		}
	}
	if err := w.q.DeleteImageWatermarks(w.ctx, sqlcgen.DeleteImageWatermarksParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID}); err != nil {
		return err
	}
	for i, watermark := range d.ImageWatermarks {
		params := sqlcgen.PutImageWatermarkParams{Partition: k.Scope.Partition, AccountID: k.Scope.AccountID, Region: k.Scope.Region, ResourceID: k.ID, Position: int64(i), SourceImageID: nullableString(watermark.SourceImageId), SourceImageRegion: nullableString(watermark.SourceImageRegion), WatermarkKey: nullableString(watermark.WatermarkKey)}
		if watermark.SourceImageCreationTime != nil {
			params.SourceImageCreationTime = sql.NullTime{Time: *watermark.SourceImageCreationTime, Valid: true}
		}
		if watermark.WatermarkCreationTime != nil {
			params.WatermarkCreationTime = sql.NullTime{Time: *watermark.WatermarkCreationTime, Valid: true}
		}
		if err := w.q.PutImageWatermark(w.ctx, params); err != nil {
			return err
		}
	}
	return nil
}
