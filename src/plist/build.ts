import plist from "plist";
export type PlistValue =
  | string
  | number
  | boolean
  | Date
  | Buffer
  | PlistValue[]
  | PlistDict;
export interface PlistDict {
  [key: string]: PlistValue;
}
export function buildPlist(value: PlistValue): string {
  const validate = (v: PlistValue, depth: number): void => {
    if (depth > 48) throw new Error("Plist nesting limit exceeded");
    if (v === null || v === undefined)
      throw new Error("Plist has no null type");
    if (typeof v === "number" && !Number.isFinite(v))
      throw new Error("Invalid plist number");
    if (v instanceof Date && !Number.isFinite(v.getTime()))
      throw new Error("Invalid plist date");
    if (typeof v === "object" && !Buffer.isBuffer(v) && !(v instanceof Date))
      Object.values(v).forEach((child) => validate(child, depth + 1));
  };
  validate(value, 0);
  return plist.build(value);
}
