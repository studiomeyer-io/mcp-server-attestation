import { describe, it, expect } from "vitest";
import { sanitizeArgs, evalArgRule, type SpawnRule, type ArgRule } from "../src/index.js";

const shellRule: SpawnRule = {
  command: "/usr/bin/echo",
  args: [{ name: "msg", kind: "shellSafeString", required: true, maxLength: 256 }],
  maxTotalArgLength: 1024,
};

describe("argument sanitizer — default-deny shell metacharacters", () => {
  it("accepts a plain string", () => {
    const r = sanitizeArgs(["hello"], shellRule);
    expect(r.allowed).toBe(true);
  });

  it.each([
    // Command substitution / param expansion
    ["semicolon", "a;b"],
    ["pipe", "a|b"],
    ["backtick", "a`b"],
    ["dollar-paren", "a$(b)"],
    ["paren-open", "a(b"],
    ["paren-close", "a)b"],
    ["dollar", "a$b"],
    // Redirects
    ["redirect", "a>b"],
    ["redirect-in", "a<b"],
    // Control / separators
    ["ampersand", "a&b"],
    ["backslash", "a\\b"],
    // Globbing — F1 fix Round 1.5
    ["glob-star", "etc/p*sswd"],
    ["glob-question", "f?le"],
    ["glob-bracket-open", "[a-z]"],
    ["glob-bracket-close", "a]b"],
    ["brace-open", "a{b"],
    ["brace-close", "a}b"],
    // Tilde / history / comment / quotes / TAB — F1 fix Round 1.5
    ["tilde-home", "~root/.ssh/id_rsa"],
    ["history-bang", "a!b"],
    ["comment-hash", "a#b"],
    ["single-quote", "a'b"],
    ["double-quote", "a\"b"],
    ["tab", "a\tb"],
  ])("blocks ASCII metacharacter: %s", (_label, payload) => {
    const r = sanitizeArgs([payload], shellRule);
    expect(r.allowed).toBe(false);
    expect(r.blockedReasons.join(" ")).toMatch(/forbidden character/);
  });

  it.each([
    ["null", "\u0000"],
    ["LF", "a\nb"],
    ["CR", "a\rb"],
    ["zero-width-space", "a\u200bb"],
    ["RTL-override", "a\u202eb"],
    ["paragraph-sep", "a\u2029b"],
    ["BOM", "a\ufeffb"],
    ["isolate", "a\u2068b"],
  ])("blocks unicode injection: %s", (_label, payload) => {
    const r = sanitizeArgs([payload], shellRule);
    expect(r.allowed).toBe(false);
  });

  // HIGH-1 fix Round 3: Fullwidth ASCII confusables (U+FF01-U+FF5E).
  // Without this block, every blocked ASCII metacharacter has a fullwidth
  // equivalent that bypasses the sanitizer.
  it.each([
    ["FULLWIDTH EXCLAMATION", "a！b"],
    ["FULLWIDTH QUOTATION", "a＂b"],
    ["FULLWIDTH NUMBER SIGN", "a＃b"],
    ["FULLWIDTH DOLLAR SIGN", "a＄b"],
    ["FULLWIDTH AMPERSAND", "a＆b"],
    ["FULLWIDTH APOSTROPHE", "a＇b"],
    ["FULLWIDTH LEFT PAREN", "a（b"],
    ["FULLWIDTH RIGHT PAREN", "a）b"],
    ["FULLWIDTH ASTERISK", "a＊b"],
    ["FULLWIDTH SEMICOLON", "a；b"],
    ["FULLWIDTH LESS-THAN", "a＜b"],
    ["FULLWIDTH GREATER-THAN", "a＞b"],
    ["FULLWIDTH QUESTION MARK", "a？b"],
    ["FULLWIDTH LEFT BRACKET", "a［b"],
    ["FULLWIDTH BACKSLASH", "a＼b"],
    ["FULLWIDTH RIGHT BRACKET", "a］b"],
    ["FULLWIDTH GRAVE", "a｀b"],
    ["FULLWIDTH LEFT BRACE", "a｛b"],
    ["FULLWIDTH PIPE", "a｜b"],
    ["FULLWIDTH RIGHT BRACE", "a｝b"],
    ["FULLWIDTH TILDE", "a～b"],
  ])("HIGH-1 blocks fullwidth confusable: %s", (_label, payload) => {
    const r = sanitizeArgs([payload], shellRule);
    expect(r.allowed).toBe(false);
  });

  it("HIGH-1 blocks the canonical bypass payload (FULLWIDTH `$(rm -rf)`)", () => {
    // FULLWIDTH DOLLAR + FULLWIDTH LEFT PAREN + payload + FULLWIDTH RIGHT PAREN
    const payload = "＄（rm -rf）";
    const r = sanitizeArgs([payload], shellRule);
    expect(r.allowed).toBe(false);
  });

  it("HIGH-1 still allows plain Latin/ASCII text (no over-reach)", () => {
    const r = sanitizeArgs(["hello-world_42"], shellRule);
    expect(r.allowed).toBe(true);
  });

  it("HIGH-1 redundant `$(` removed — `$(...)` still blocked via individual rules", () => {
    const r = sanitizeArgs(["a$(b)"], shellRule);
    expect(r.allowed).toBe(false);
    // No reason should report the literal trigraph as a single forbidden token.
    const trigraphHits = r.blockedReasons.filter((m) =>
      m.includes('"$("'),
    ).length;
    expect(trigraphHits).toBe(0);
  });

  it("rejects argv longer than maxTotalArgLength", () => {
    const r = sanitizeArgs([Array(2000).fill("a").join("")], {
      ...shellRule,
      args: [{ name: "msg", kind: "shellSafeString", required: true, maxLength: 9999 }],
      maxTotalArgLength: 100,
    });
    expect(r.allowed).toBe(false);
    expect(r.blockedReasons.join(" ")).toMatch(/maxTotalArgLength/);
  });

  it("rejects extra positional args", () => {
    const r = sanitizeArgs(["a", "b", "c"], shellRule);
    expect(r.allowed).toBe(false);
  });

  it("missing required arg is rejected", () => {
    const r = sanitizeArgs([], shellRule);
    expect(r.allowed).toBe(false);
    expect(r.blockedReasons.join(" ")).toMatch(/missing required/);
  });
});

describe("evalArgRule — per-rule kind coverage", () => {
  const cases: Array<[string, ArgRule, string, boolean]> = [
    ["regex match", { name: "x", kind: "regex", required: true, pattern: "^[a-z]+$" }, "hello", true],
    ["regex miss", { name: "x", kind: "regex", required: true, pattern: "^[a-z]+$" }, "Hello", false],
    ["enum hit", { name: "x", kind: "enum", required: true, values: ["a", "b"] }, "a", true],
    ["enum miss", { name: "x", kind: "enum", required: true, values: ["a", "b"] }, "c", false],
    ["length ok", { name: "x", kind: "length", required: true, min: 1, max: 4 }, "abc", true],
    ["length too long", { name: "x", kind: "length", required: true, min: 1, max: 4 }, "abcde", false],
    ["prefix ok", { name: "x", kind: "prefix", required: true, prefix: "/safe/", maxSuffixLength: 64 }, "/safe/x", true],
    ["prefix miss", { name: "x", kind: "prefix", required: true, prefix: "/safe/", maxSuffixLength: 64 }, "/etc/x", false],
    ["literal hit", { name: "x", kind: "literal", required: true, value: "exact" }, "exact", true],
    ["literal miss", { name: "x", kind: "literal", required: true, value: "exact" }, "Exact", false],
  ];

  for (const [label, rule, value, expectOk] of cases) {
    it(label, () => {
      const reasons = evalArgRule(value, rule);
      expect(reasons.length === 0).toBe(expectOk);
    });
  }

  it("non-string value is rejected", () => {
    const reasons = evalArgRule(42, { name: "x", kind: "shellSafeString", required: true, maxLength: 64 });
    expect(reasons.length).toBeGreaterThan(0);
  });
});
