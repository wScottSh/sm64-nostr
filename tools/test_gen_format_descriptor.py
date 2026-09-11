#!/usr/bin/env python3
"""
Unit tests for gen_format_descriptor.py's N-variable-length-field support
(spec #109, sub-issue #110): a descriptor with TWO variable-length fields
(mirroring format v3's real TAG_LEN/TAG + NAME_LEN/NAME shape) must render
PIPELINE_FMT_OFF_SIG(tagLen, nameLen), correct PIPELINE_FMT_FIXED_SIZE /
PIPELINE_FMT_TOTAL_SIZE(...) / PIPELINE_FMT_MAX_TOTAL_SIZE, and must no
longer raise the old "only one variable-length field is supported" v2
hard-fail. Mirrors the CLI-subprocess-invocation style already established
by tools/test_gen_event_profile.py.

Also exercises the real committed src/pipeline/format_descriptor.json (v3,
two variable-length fields: TAG, NAME) end to end, and a zero-variable-field
descriptor, to pin the generator's behavior across 0/1/2 variable fields.

Run directly:   python tools/test_gen_format_descriptor.py
Or via pytest:  python -m pytest tools/test_gen_format_descriptor.py
Or unittest:    python -m unittest tools.test_gen_format_descriptor
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TOOLS_DIR)
SCRIPT = os.path.join(TOOLS_DIR, "gen_format_descriptor.py")
REAL_DESCRIPTOR_JSON = os.path.join(REPO_ROOT, "src", "pipeline", "format_descriptor.json")


def run_generator(descriptor, tmpdir, name="descriptor.json"):
    """Writes `descriptor` (a dict) as JSON, runs the real script against
    it via subprocess (exactly how both the ROM build and the host test
    Makefile invoke it), and returns (returncode, stdout, stderr, header_text_or_None)."""
    json_path = os.path.join(tmpdir, name)
    out_path = os.path.join(tmpdir, "format_descriptor.h")
    with open(json_path, "w") as f:
        json.dump(descriptor, f)
    result = subprocess.run(
        [sys.executable, SCRIPT, "--json", json_path, "--out", out_path],
        capture_output=True, text=True,
    )
    header_text = None
    if os.path.exists(out_path):
        with open(out_path, "r") as f:
            header_text = f.read()
    return result.returncode, result.stdout, result.stderr, header_text


TWO_VAR_DESCRIPTOR = {
    "format_tag": 3,
    "fields": [
        {"name": "FORMAT_TAG", "size": 1},
        {"name": "COURSE", "size": 1},
        {"name": "TAG_LEN", "size": 1},
        {"name": "TAG", "var_len": True, "len_field": "TAG_LEN", "max_size": 10},
        {"name": "NAME_LEN", "size": 1},
        {"name": "NAME", "var_len": True, "len_field": "NAME_LEN", "max_size": 15},
        {"name": "SIG", "size": 64},
    ],
}

ZERO_VAR_DESCRIPTOR = {
    "format_tag": 1,
    "fields": [
        {"name": "FORMAT_TAG", "size": 1},
        {"name": "COURSE", "size": 1},
        {"name": "SIG", "size": 64},
    ],
}

ONE_VAR_DESCRIPTOR = {
    "format_tag": 2,
    "fields": [
        {"name": "FORMAT_TAG", "size": 1},
        {"name": "TAG_LEN", "size": 1},
        {"name": "TAG", "var_len": True, "len_field": "TAG_LEN", "max_size": 10},
        {"name": "SIG", "size": 64},
    ],
}


class TwoVariableFieldDescriptorTests(unittest.TestCase):
    """The N-variable-length-field generalization's core acceptance
    criterion (sub-issue #110): a second variable-length field no longer
    raises, and SIG's offset macro takes BOTH preceding var lengths, in
    declaration order."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="gen_format_descriptor_test_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_second_variable_field_no_longer_raises(self):
        rc, _stdout, stderr, header = run_generator(TWO_VAR_DESCRIPTOR, self.tmpdir)
        self.assertEqual(rc, 0, stderr)
        self.assertIsNotNone(header)
        self.assertNotIn("only one variable-length field is supported", stderr)

    def test_sig_offset_macro_takes_both_preceding_var_lengths_in_order(self):
        _rc, _stdout, _stderr, header = run_generator(TWO_VAR_DESCRIPTOR, self.tmpdir)
        self.assertIn("#define PIPELINE_FMT_OFF_SIG(tagLen, nameLen)", header)

    def test_name_len_offset_macro_takes_only_the_tag_length(self):
        # NAME_LEN's own offset depends on TAG (the one variable field
        # preceding it), NOT on NAME itself -- it must take exactly one
        # parameter, not both.
        _rc, _stdout, _stderr, header = run_generator(TWO_VAR_DESCRIPTOR, self.tmpdir)
        self.assertIn("#define PIPELINE_FMT_OFF_NAME_LEN(tagLen)", header)
        self.assertNotIn("PIPELINE_FMT_OFF_NAME_LEN(tagLen, nameLen)", header)

    def test_fields_before_any_variable_field_get_plain_constant_offsets(self):
        _rc, _stdout, _stderr, header = run_generator(TWO_VAR_DESCRIPTOR, self.tmpdir)
        self.assertIn("#define PIPELINE_FMT_OFF_FORMAT_TAG  0u", header)
        self.assertIn("#define PIPELINE_FMT_OFF_COURSE  1u", header)

    def test_fixed_size_sums_every_fixed_field_including_both_len_prefixes(self):
        # FORMAT_TAG(1) + COURSE(1) + TAG_LEN(1) + NAME_LEN(1) + SIG(64) = 68.
        _rc, _stdout, _stderr, header = run_generator(TWO_VAR_DESCRIPTOR, self.tmpdir)
        self.assertIn("#define PIPELINE_FMT_FIXED_SIZE 68u", header)

    def test_total_size_macro_takes_both_var_lengths_and_sums_correctly(self):
        _rc, _stdout, _stderr, header = run_generator(TWO_VAR_DESCRIPTOR, self.tmpdir)
        self.assertIn(
            "#define PIPELINE_FMT_TOTAL_SIZE(tagLen, nameLen) "
            "(PIPELINE_FMT_FIXED_SIZE + (tagLen) + (nameLen))",
            header,
        )

    def test_max_total_size_sums_both_max_sizes_onto_fixed_size(self):
        # 68 (fixed) + 10 (TAG max) + 15 (NAME max) = 93.
        _rc, _stdout, _stderr, header = run_generator(TWO_VAR_DESCRIPTOR, self.tmpdir)
        self.assertIn("#define PIPELINE_FMT_MAX_TOTAL_SIZE 93u", header)

    def test_each_variable_field_gets_its_own_max_size_macro(self):
        _rc, _stdout, _stderr, header = run_generator(TWO_VAR_DESCRIPTOR, self.tmpdir)
        self.assertIn("#define PIPELINE_FMT_MAX_SIZE_TAG 10u", header)
        self.assertIn("#define PIPELINE_FMT_MAX_SIZE_NAME 15u", header)

    def test_format_tag_value_rendered(self):
        _rc, _stdout, _stderr, header = run_generator(TWO_VAR_DESCRIPTOR, self.tmpdir)
        self.assertIn("#define PIPELINE_FMT_TAG_VALUE 3u", header)


class ZeroAndOneVariableFieldDescriptorTests(unittest.TestCase):
    """The generalization must not regress the 0-var and 1-var cases the
    generator already supported (format v0-ish / format v2's own shape)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="gen_format_descriptor_test_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_zero_variable_fields_emits_plain_constant_total_size(self):
        _rc, _stdout, _stderr, header = run_generator(ZERO_VAR_DESCRIPTOR, self.tmpdir)
        # FORMAT_TAG(1) + COURSE(1) + SIG(64) = 66, no variable fields at all.
        self.assertIn("#define PIPELINE_FMT_FIXED_SIZE 66u", header)
        self.assertIn("#define PIPELINE_FMT_TOTAL_SIZE 66u", header)
        self.assertIn("#define PIPELINE_FMT_MAX_TOTAL_SIZE 66u", header)
        self.assertNotIn("#define PIPELINE_FMT_TOTAL_SIZE(", header)

    def test_one_variable_field_matches_pre_v3_single_param_shape(self):
        _rc, _stdout, _stderr, header = run_generator(ONE_VAR_DESCRIPTOR, self.tmpdir)
        self.assertIn("#define PIPELINE_FMT_OFF_SIG(tagLen)", header)
        self.assertIn("#define PIPELINE_FMT_TOTAL_SIZE(tagLen) (PIPELINE_FMT_FIXED_SIZE + (tagLen))", header)


class RealFormatDescriptorJsonTests(unittest.TestCase):
    """End-to-end against the actual committed src/pipeline/format_descriptor.json
    (format v3): confirms the real descriptor renders successfully with the
    exact NAME_LEN/NAME shape spec #109/#110 requires."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="gen_format_descriptor_test_")
        self.out_path = os.path.join(self.tmpdir, "format_descriptor.h")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def run_real_descriptor(self):
        return subprocess.run(
            [sys.executable, SCRIPT, "--json", REAL_DESCRIPTOR_JSON, "--out", self.out_path],
            capture_output=True, text=True,
        )

    def test_real_descriptor_renders_without_raising(self):
        result = self.run_real_descriptor()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.exists(self.out_path))

    def test_real_descriptor_is_format_tag_3(self):
        self.run_real_descriptor()
        with open(self.out_path) as f:
            header = f.read()
        self.assertIn("#define PIPELINE_FMT_TAG_VALUE 3u", header)

    def test_real_descriptor_has_name_len_and_name_fields_before_sig(self):
        self.run_real_descriptor()
        with open(self.out_path) as f:
            header = f.read()
        self.assertIn("PIPELINE_FMT_OFF_NAME_LEN(tagLen)", header)
        self.assertIn("PIPELINE_FMT_OFF_NAME(tagLen)", header)
        self.assertIn("PIPELINE_FMT_OFF_SIG(tagLen, nameLen)", header)
        self.assertIn("#define PIPELINE_FMT_MAX_SIZE_NAME 17u", header)

    def test_real_descriptor_json_declares_no_star_coord(self):
        # ADR-0007 / docs/format-v3-spec.md explicitly reject star_coord;
        # this is a structural guard against it creeping back in.
        with open(REAL_DESCRIPTOR_JSON) as f:
            text = f.read()
        self.assertNotIn("star_coord", text)
        self.assertNotIn("STAR_COORD", text)


if __name__ == "__main__":
    unittest.main()
