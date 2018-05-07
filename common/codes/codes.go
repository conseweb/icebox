package codes

//go:generate go-enum -f=codes.go --noprefix --marshal --lower

// Code is an enumeration of codes that are allowed.
// ENUM(
// OK, Canceled, Unknown
// InvalidArgument
// DeadlineExceeded
// NotFound
// AlreadyExists
// PermissionDenied
// ResourceExhausted
// FailedPrecondition
// Aborted
// OutOfRange
// Unimplemented
// Internal
// Unavailable
// DataLoss
// Unauthenticated
// )
type Code uint32
