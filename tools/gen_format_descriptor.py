#!/usr/bin/env python3
"""
Render the packed-payload format descriptor (spec #24, sub-issue #26; format
v2 variable-length tag support added for spec #52, sub-issue #54; format v3
generalizes to N variable-length fields, spec #109, sub-issue #110) from its
single JSON source (src/pipeline/format_descriptor.json) into a C header.
Run twice -- once for the ROM build (into $(BUILD_DIR)/include) and once for
the host test tool (into tools/pipeline_test/build/include) -- from the
identical JSON input, so the ROM pack adapter and the host unpack adapter can
never disagree on field offsets/sizes. This mirrors the "same pure source
compiled twice" precedent from sub-issue #25, applied to a generated header
instead of a hand-written .c file.

Format v3 supports N variable-length fields (originally at-most-one in
format v2): a field descriptor with "var_len": true, "len_field" (the name
of the fixed-size field elsewhere in the layout whose runtime VALUE gives
this field's actual length), and "max_size" (the largest that length can
legally be, used to size host-side decode buffers and the compile-time
QR-fits guard).

Every field's start offset is the sum of (a) every FIXED-size field's width
that precedes it, plus (b) the runtime length of every VARIABLE-length field
that precedes it. The first part is a plain compile-time constant; the
second is only known at runtime, so any field with at least one variable
field ahead of it cannot have a fixed compile-time offset -- the generator
instead emits its offset as a function-like macro taking the ordered runtime
lengths of every preceding variable field, e.g. PIPELINE_FMT_OFF_SIG(tagLen,
nameLen) once two variable fields (TAG, NAME) precede SIG. Each such
parameter is named after its variable field: <lowercased field name>Len (TAG
-> tagLen, NAME -> nameLen), in the order those variable fields appear in
the descriptor.

PIPELINE_FMT_FIXED_SIZE is the total size assuming every variable field
contributes zero bytes (i.e. the sum of every fixed-size field's width).
PIPELINE_FMT_TOTAL_SIZE(...) is the real total for a given set of runtime
variable-field lengths (same ordered parameter list as the OFF_* macros
above), and PIPELINE_FMT_MAX_TOTAL_SIZE is the worst-case total (every
variable field at its own max_size), the right size for host-side
decode/scratch buffers that must hold any legal incoming payload.

With zero variable fields, PIPELINE_FMT_TOTAL_SIZE is a plain compile-time
constant (no parameters), matching PIPELINE_FMT_FIXED_SIZE /
PIPELINE_FMT_MAX_TOTAL_SIZE exactly.

Usage: gen_format_descriptor.py --json <path> --out <path>
"""
import argparse
import json
import os
import sys


def _var_param_name(var_field_name):
    """The runtime-length parameter name a variable field contributes to
    every function-like offset/total-size macro after it, e.g. TAG ->
    "tagLen", NAME -> "nameLen"."""
    return var_field_name.lower() + "Len"


def _offset_expr(int_part, preceding_var_names):
    """Render an offset as a C expression: a plain integer literal if no
    variable field precedes it, otherwise the integer part plus each
    preceding variable field's runtime length parameter, added in order."""
    if not preceding_var_names:
        return "%uu" % int_part
    terms = ["%uu" % int_part] + ["(%s)" % _var_param_name(n) for n in preceding_var_names]
    return "(" + " + ".join(terms) + ")"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.json, "r") as f:
        descriptor = json.load(f)

    fields = descriptor["fields"]
    format_tag = descriptor["format_tag"]

    int_part = 0            # running sum of fixed-field widths seen so far
    preceding_vars = []      # ordered names of variable fields seen so far
    field_offsets = []       # (name, int_part, list(preceding_vars), size_or_None)
    var_fields = []          # (name, int_part_at_start, list(preceding_vars_before_it), len_field, max_size)

    for field in fields:
        name = field["name"]
        if field.get("var_len"):
            var_fields.append({
                "name": name,
                "int_part": int_part,
                "preceding": list(preceding_vars),
                "len_field": field["len_field"],
                "max_size": field["max_size"],
            })
            field_offsets.append((name, int_part, list(preceding_vars), None))
            preceding_vars.append(name)
        else:
            size = field["size"]
            field_offsets.append((name, int_part, list(preceding_vars), size))
            int_part += size

    fixed_size = int_part
    max_total_size = fixed_size + sum(v["max_size"] for v in var_fields)
    param_names = [_var_param_name(v["name"]) for v in var_fields]
    param_list = ", ".join(param_names)

    lines = []
    lines.append("#ifndef PIPELINE_FORMAT_DESCRIPTOR_H")
    lines.append("#define PIPELINE_FORMAT_DESCRIPTOR_H")
    lines.append("")
    lines.append("/*")
    lines.append(" * GENERATED by tools/gen_format_descriptor.py from the single-source")
    lines.append(" * descriptor src/pipeline/format_descriptor.json -- DO NOT EDIT (spec #24,")
    lines.append(" * sub-issue #26; format v2 variable-length tag, spec #52 sub-issue #54;")
    lines.append(" * format v3 N variable-length fields, spec #109 sub-issue #110).")
    lines.append(" * Both the ROM pack adapter and the host unpack adapter include this")
    lines.append(" * generated header (rendered separately into each build's own include")
    lines.append(" * dir from the identical JSON), so field offsets/sizes can never drift")
    lines.append(" * between the two sides of the QR payload seam.")
    lines.append(" */")
    lines.append("")
    lines.append("#define PIPELINE_FMT_TAG_VALUE %uu" % format_tag)
    lines.append("#define PIPELINE_FMT_FIELD_COUNT %uu" % len(fields))
    lines.append("")

    for name, off_int, preceding, size in field_offsets:
        offset_expr = _offset_expr(off_int, preceding)
        if preceding:
            local_param_list = ", ".join(_var_param_name(n) for n in preceding)
            lines.append("#define PIPELINE_FMT_OFF_%s(%s)  %s" % (name, local_param_list, offset_expr))
        else:
            lines.append("#define PIPELINE_FMT_OFF_%s  %s" % (name, offset_expr))
        if size is not None:
            lines.append("#define PIPELINE_FMT_SIZE_%s %uu" % (name, size))

    if var_fields:
        lines.append("")
        lines.append("/* Variable-length fields: each one's actual length is the runtime VALUE")
        lines.append(" * of its own len_field (a fixed-size field above), capped at its own")
        lines.append(" * MAX_SIZE below. */")
        for v in var_fields:
            lines.append("#define PIPELINE_FMT_MAX_SIZE_%s %uu" % (v["name"], v["max_size"]))

    lines.append("")
    lines.append("/* PIPELINE_FMT_FIXED_SIZE: total size with every variable field contributing")
    lines.append(" * zero bytes (i.e. the sum of every fixed-size field). PIPELINE_FMT_TOTAL_SIZE(...)")
    if var_fields:
        lines.append(" * (params: %s) is the real total for the given runtime variable-field" % param_list)
        lines.append(" * lengths; PIPELINE_FMT_MAX_TOTAL_SIZE is the worst-case total (every variable")
        lines.append(" * field at its own max), the right bound for host-side decode/scratch buffers")
        lines.append(" * that must hold any legal incoming payload. */")
    else:
        lines.append(" * equals PIPELINE_FMT_FIXED_SIZE when there are no variable-length fields. */")
    lines.append("#define PIPELINE_FMT_FIXED_SIZE %uu" % fixed_size)
    if var_fields:
        total_terms = ["PIPELINE_FMT_FIXED_SIZE"] + ["(%s)" % p for p in param_names]
        lines.append("#define PIPELINE_FMT_TOTAL_SIZE(%s) (%s)" % (param_list, " + ".join(total_terms)))
        lines.append("#define PIPELINE_FMT_MAX_TOTAL_SIZE %uu" % max_total_size)
    else:
        lines.append("#define PIPELINE_FMT_TOTAL_SIZE %uu" % fixed_size)
        lines.append("#define PIPELINE_FMT_MAX_TOTAL_SIZE %uu" % fixed_size)
    lines.append("")
    lines.append("#endif /* PIPELINE_FORMAT_DESCRIPTOR_H */")
    lines.append("")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    sys.exit(main())
