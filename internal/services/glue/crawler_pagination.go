package glue

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"

	api "stackd/internal/awsapi/glue"
)

func crawlerPage(scope Scope, kind, filter string, token *api.Token, limit *api.PageSize, length int) (int, int, *api.Token, error) {
	size := 100
	if limit != nil {
		size = int(*limit)
	}
	if size < 1 || size > 1000 {
		return 0, 0, nil, failure("InvalidInputException", "Invalid maximum number of results.")
	}
	hash := sha256.Sum256([]byte(scope.Partition + "\x00" + scope.AccountID + "\x00" + scope.Region + "\x00" + kind + "\x00" + filter))
	binding := hex.EncodeToString(hash[:16]) + ":"
	start := 0
	if token != nil {
		decoded, err := base64.RawURLEncoding.DecodeString(string(*token))
		if err != nil || !strings.HasPrefix(string(decoded), binding) {
			return 0, 0, nil, failure("InvalidInputException", "Invalid pagination token.")
		}
		start, err = strconv.Atoi(strings.TrimPrefix(string(decoded), binding))
		if err != nil || start < 0 || start > length {
			return 0, 0, nil, failure("InvalidInputException", "Invalid pagination token.")
		}
	}
	end := min(start+size, length)
	var next *api.Token
	if end < length {
		next = new(api.Token(base64.RawURLEncoding.EncodeToString([]byte(binding + strconv.Itoa(end)))))
	}
	return start, end, next, nil
}
