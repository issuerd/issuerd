export type JsonObject = Record<string, unknown>;

export const ADMIN_PAGE_SIZE = 100;

export async function findInPages(
  loadPage: (first: number, max: number) => Promise<unknown>,
  label: string,
  predicate: (entry: JsonObject) => boolean,
  pageSize = ADMIN_PAGE_SIZE,
): Promise<JsonObject | undefined> {
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > ADMIN_PAGE_SIZE) {
    throw new Error("page size must be an integer between 1 and 100");
  }
  for (let first = 0; ; first += pageSize) {
    const value = await loadPage(first, pageSize);
    if (!Array.isArray(value)) throw new Error(`${label} was not an array`);
    const page = value.map((entry) => {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
        throw new Error(`${label} contained a non-object entry`);
      }
      return entry as JsonObject;
    });
    const found = page.find(predicate);
    if (found) return found;
    if (page.length < pageSize) return undefined;
  }
}
