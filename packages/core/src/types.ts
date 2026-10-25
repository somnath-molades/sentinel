// Shared domain types; later tasks add them here.
export type Result<T, E> = { ok: true; value: T } | { ok: false; error: E }
