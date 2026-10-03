package s3

import "stackd/storage/memory"

type accountPublicAccessKey struct {
	partition, accountID string
}

func (r memoryReader) AccountPublicAccessBlock(partition, accountID string) (*PublicAccessBlock, error) {
	var out *PublicAccessBlock
	err := r.repository.accountPublicAccess.View(r.Context(), func(state *map[accountPublicAccessKey]PublicAccessBlock, _ *memory.Transaction) error {
		if block, ok := (*state)[accountPublicAccessKey{partition: partition, accountID: accountID}]; ok {
			out = &block
		}
		return nil
	})
	return out, err
}

func (w memoryWriter) PutAccountPublicAccessBlock(partition, accountID string, block PublicAccessBlock) error {
	return w.repository.accountPublicAccess.Update(w.Context(), func(state *map[accountPublicAccessKey]PublicAccessBlock, _ *memory.Transaction) error {
		(*state)[accountPublicAccessKey{partition: partition, accountID: accountID}] = block
		return nil
	})
}

func (w memoryWriter) DeleteAccountPublicAccessBlock(partition, accountID string) error {
	return w.repository.accountPublicAccess.Update(w.Context(), func(state *map[accountPublicAccessKey]PublicAccessBlock, _ *memory.Transaction) error {
		delete(*state, accountPublicAccessKey{partition: partition, accountID: accountID})
		return nil
	})
}
