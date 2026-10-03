package stackd

import "stackd/internal/services/account"

// EmailSender supplies control-plane verification delivery. Use mail.NewSMTP
// with a local relay, or provide an implementation that honors cancellation.
type EmailSender = account.EmailSender
