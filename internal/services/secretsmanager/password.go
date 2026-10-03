package secretsmanager

import (
	"crypto/rand"
	"strings"

	api "stackd/internal/awsapi/secretsmanager"
)

// randomIndex uses rejection sampling rather than a biased byte modulo. The
// small buffer amortizes operating-system randomness across password characters.
type passwordRandom struct {
	bytes [256]byte
	used  int
}

func (r *passwordRandom) index(size int) (int, error) {
	limit := 256 - 256%size
	for {
		if r.used == len(r.bytes) {
			if _, err := rand.Read(r.bytes[:]); err != nil {
				return 0, err
			}
			r.used = 0
		}
		n := int(r.bytes[r.used])
		r.used++
		if n < limit {
			return n % size, nil
		}
	}
}

func (s *Service) getRandomPassword(tx Transaction, in *api.GetRandomPasswordInput) (*api.GetRandomPasswordOutput, error) {
	if err := s.authorize(tx, "GetRandomPassword", SecretRecord{}, nil); err != nil {
		return nil, err
	}
	length := 32
	if in.PasswordLength != nil {
		if *in.PasswordLength < 1 || *in.PasswordLength > 4096 {
			return nil, failure("InvalidParameterException", "PasswordLength must be between 1 and 4096.")
		}
		length = int(*in.PasswordLength)
	}
	exclude := value(in.ExcludeCharacters)
	if len(exclude) > 4096 {
		return nil, failure("InvalidParameterException", "ExcludeCharacters must not exceed 4096 characters.")
	}
	var groups []string
	include := func(chars string, enabled bool) {
		if !enabled {
			return
		}
		chars = strings.Map(func(char rune) rune {
			if strings.ContainsRune(exclude, char) {
				return -1
			}
			return char
		}, chars)
		if chars != "" {
			groups = append(groups, chars)
		}
	}
	include("abcdefghijklmnopqrstuvwxyz", in.ExcludeLowercase == nil || !bool(*in.ExcludeLowercase))
	include("ABCDEFGHIJKLMNOPQRSTUVWXYZ", in.ExcludeUppercase == nil || !bool(*in.ExcludeUppercase))
	include("0123456789", in.ExcludeNumbers == nil || !bool(*in.ExcludeNumbers))
	include("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", in.ExcludePunctuation == nil || !bool(*in.ExcludePunctuation))
	include(" ", in.IncludeSpace != nil && bool(*in.IncludeSpace))
	if len(groups) == 0 {
		return nil, failure("InvalidParameterException", "The specified exclusions leave no characters available for the password.")
	}
	requireEach := in.RequireEachIncludedType == nil || bool(*in.RequireEachIncludedType)
	if requireEach && length < len(groups) {
		return nil, failure("InvalidParameterException", "PasswordLength is too short to include at least one character of each included type.")
	}
	alphabet := strings.Join(groups, "")
	password := make([]byte, length)
	defer clear(password)
	random := passwordRandom{used: 256}
	defer clear(random.bytes[:])
	for i := range password {
		index, err := random.index(len(alphabet))
		if err != nil {
			return nil, err
		}
		password[i] = alphabet[index]
	}
	if requireEach {
		// Select distinct random positions without replacement. The remaining
		// positions retain independent samples from the complete alphabet.
		var positions [5]int
		for i, group := range groups {
			// A password can exceed 256 characters, so combine two independent
			// bytes before rejection-sampling the position range.
			var position int
			for {
				lo, err := random.index(256)
				if err != nil {
					return nil, err
				}
				hi, err := random.index(256)
				if err != nil {
					return nil, err
				}
				n := hi*256 + lo
				if n < 65536-65536%length {
					position = n % length
					duplicate := false
					for _, previous := range positions[:i] {
						if previous == position {
							duplicate = true
							break
						}
					}
					if !duplicate {
						break
					}
				}
			}
			positions[i] = position
			index, err := random.index(len(group))
			if err != nil {
				return nil, err
			}
			password[positions[i]] = group[index]
		}
	}
	return &api.GetRandomPasswordOutput{RandomPassword: str[api.RandomPasswordType](string(password))}, nil
}
