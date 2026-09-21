import plist from "plist";
import bplist from "bplist-parser";
import type { PlistDict, PlistValue } from "./build.js";
export const MAX_BODY = 4 * 1024 * 1024;
export class PlistParseError extends Error {
  readonly prefixHex: string;
  constructor(message: string, body: Buffer) {
    super(message);
    this.name = "PlistParseError";
    this.prefixHex = body.subarray(0, 256).toString("hex");
  }
}
export function sniffPlistFormat(buf: Buffer): "binary" | "xml" | "unknown" {
  if (buf.subarray(0, 8).toString("ascii") === "bplist00") return "binary";
  return buf
    .toString("utf8")
    .replace(/^\uFEFF/, "")
    .trimStart()
    .startsWith("<")
    ? "xml"
    : "unknown";
}
export function normalize(
  value: unknown,
  depth = 0,
  seen = new Set<object>(),
): PlistValue {
  if (depth > 48) throw new Error("Plist depth limit exceeded");
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (value instanceof Date && Number.isFinite(value.getTime())) return value;
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value !== "object" || value === null)
    throw new Error("Unsupported plist value");
  if (seen.has(value)) throw new Error("Cyclic plist");
  seen.add(value);
  try {
    if (Array.isArray(value))
      return value.map((v) => normalize(v, depth + 1, seen));
    const out: PlistDict = Object.create(null) as PlistDict;
    for (const [key, child] of Object.entries(value)) {
      if (["__proto__", "constructor", "prototype"].includes(key))
        throw new Error("Unsafe dictionary key");
      out[key] = normalize(child, depth + 1, seen);
    }
    return out;
  } finally {
    seen.delete(value);
  }
}
// Check the binary object graph BEFORE invoking the recursive library parser.
function checkBinary(buf: Buffer): void {
  if (buf.length < 40) throw new Error("Truncated binary plist");
  const t = buf.length - 32;
  const os = buf[t + 6] ?? 0;
  const rs = buf[t + 7] ?? 0;
  const read = (at: number, size: number): number => {
    if (size < 1 || size > 8 || at < 0 || at + size > buf.length)
      throw new Error("Invalid binary offset");
    let n = 0n;
    for (let i = 0; i < size; i++) n = (n << 8n) | BigInt(buf[at + i] ?? 0);
    if (n > BigInt(Number.MAX_SAFE_INTEGER))
      throw new Error("Binary integer overflow");
    return Number(n);
  };
  const count = read(t + 8, 8),
    top = read(t + 16, 8),
    offsets = read(t + 24, 8);
  if (count > 100_000 || offsets + count * os > t || offsets < 8)
    throw new Error("Invalid binary object table");
  const active = new Set<number>();
  let budget = 100_000;
  const walk = (id: number, depth: number): void => {
    if (--budget < 0 || depth > 48 || active.has(id) || id >= count)
      throw new Error("Binary graph limit exceeded");
    const at = read(offsets + id * os, os);
    if (at < 8 || at >= offsets) throw new Error("Invalid object offset");
    const marker = buf[at] ?? 0;
    const type = marker >> 4;
    if (![10, 12, 13].includes(type)) return;
    let len = marker & 15;
    let start = at + 1;
    if (len === 15) {
      const int = buf[start++] ?? 0;
      if (int >> 4 !== 1) throw new Error("Invalid object length");
      const size = 2 ** (int & 15);
      len = read(start, size);
      start += size;
    }
    const refs = len * (type === 13 ? 2 : 1);
    if (refs > 100_000 || start + refs * rs > offsets)
      throw new Error("Invalid references");
    active.add(id);
    for (let i = 0; i < refs; i++) walk(read(start + i * rs, rs), depth + 1);
    active.delete(id);
  };
  walk(top, 0);
}
export function parsePlist(buf: Buffer): PlistValue | null {
  if (buf.length === 0) return null;
  try {
    if (buf.length > MAX_BODY) throw new Error("Plist body limit exceeded");
    const format = sniffPlistFormat(buf);
    if (format === "binary") {
      checkBinary(buf);
      const roots: unknown[] = bplist.parseBuffer(buf);
      if (roots.length !== 1) throw new Error("Expected one plist root");
      return normalize(roots[0]);
    }
    if (format !== "xml") throw new Error("Unknown plist format");
    const xml = buf
      .toString("utf8")
      .replace(/^\uFEFF/, "")
      .trim();
    if (/<!ENTITY|<!DOCTYPE[^>]*\[/i.test(xml))
      throw new Error("DTD entities are forbidden");
    let depth = 0;
    let count = 0;
    for (const token of xml.matchAll(/<\/?(?:dict|array)(?:\s[^>]*)?>/g)) {
      depth += token[0].startsWith("</") ? -1 : 1;
      if (depth > 48 || ++count > 100_000 || depth < 0)
        throw new Error("XML structure limit exceeded");
    }
    if (
      depth !== 0 ||
      !/<plist(?:\s|>)/.test(xml) ||
      !/<\/plist>\s*$/.test(xml)
    )
      throw new Error("Incomplete XML plist");
    return normalize(plist.parse(xml));
  } catch (e) {
    throw new PlistParseError(e instanceof Error ? e.message : String(e), buf);
  }
}
export function dict(value: unknown): PlistDict {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Buffer.isBuffer(value) ||
    value instanceof Date
  )
    throw new Error("Expected plist dictionary");
  return value as PlistDict;
}
