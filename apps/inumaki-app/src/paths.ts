/** The last component of a local path, for a folder's display name. */
export const basename = (path: string) => path.replace(/[/\\]+$/, "").split(/[/\\]/).pop() || path;
