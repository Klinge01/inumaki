/// `Debug` that prints only the listed fields, for types that also carry a
/// name, slug, path, text, token, or secret (M6 spec §6.6, §10). The list is
/// an allowlist: a field added later stays out of `Debug` until someone
/// decides it is safe to print.
macro_rules! debug_fields {
    ($t:ident { $($f:ident),* $(,)? }) => {
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($t))
                    $(.field(stringify!($f), &self.$f))*
                    .finish_non_exhaustive()
            }
        }
    };
}
