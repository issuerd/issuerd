import test from "node:test";
import assert from "node:assert/strict";
import { findInPages } from "../src/paging.js";

test("paginated lookup finds groups and members beyond the first 100 records", async () => {
  const records = Array.from({ length: 101 }, (_, index) => ({
    id: `id-${index}`,
    name: index === 100 ? "mcp-acceptance" : `other-${index}`,
  }));
  for (const target of ["mcp-acceptance", "id-100"]) {
    const calls: Array<[number, number]> = [];
    const result = await findInPages(
      (first, max) => {
        calls.push([first, max]);
        return Promise.resolve(records.slice(first, first + max));
      },
      "records",
      target === "mcp-acceptance"
        ? (entry) => entry.name === target
        : (entry) => entry.id === target,
    );
    assert.equal(result?.id, "id-100");
    assert.deepEqual(calls, [
      [0, 100],
      [100, 100],
    ]);
  }
});

test("paginated lookup checks an empty page after an exact full-page boundary", async () => {
  const records = Array.from({ length: 100 }, (_, index) => ({ id: `id-${index}` }));
  const calls: number[] = [];
  const result = await findInPages(
    (first, max) => {
      calls.push(first);
      return Promise.resolve(records.slice(first, first + max));
    },
    "records",
    () => false,
  );
  assert.equal(result, undefined);
  assert.deepEqual(calls, [0, 100]);
});

test("paginated lookup supports bounded custom pages", async () => {
  const records = [{ id: "a" }, { id: "b" }, { id: "c" }, { id: "target" }];
  const result = await findInPages(
    (first, max) => Promise.resolve(records.slice(first, first + max)),
    "records",
    (entry) => entry.id === "target",
    2,
  );
  assert.equal(result?.id, "target");
});

test("paginated lookup rejects invalid pages and page sizes", async () => {
  await assert.rejects(findInPages(() => Promise.resolve({}), "records", () => true), /was not an array/);
  await assert.rejects(findInPages(() => Promise.resolve([null]), "records", () => true), /non-object/);
  for (const pageSize of [0, -1, 101, 1.5]) {
    await assert.rejects(findInPages(() => Promise.resolve([]), "records", () => true, pageSize));
  }
});
