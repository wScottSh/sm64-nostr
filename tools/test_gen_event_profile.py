#!/usr/bin/env python3
"""
Unit tests for gen_event_profile.py's --event-name build input (spec #75,
sub-issue #76): "a nameless or invalid ROM cannot be built".

Mirrors the two kinds of prior art already in gen_event_profile.py:
  - TAG_VALUE_RE / the --tag FATAL gate (charset + length rejection, CLI-level)
  - the PIPELINE_PRIVKEY_FILE fail-closed check (required-input, build refuses
    to produce a bad binary)

Two layers, same split gen_event_profile.py itself uses:
  - Fast, in-process tests of normalize_event_name() (accept/reject/fold/
    length).
  - End-to-end CLI (subprocess) tests of main() -- required-ness, the emitted
    header, and the off-wire invariant.

Run directly:   python tools/test_gen_event_profile.py
Or via pytest:  python -m pytest tools/test_gen_event_profile.py
Or unittest:    python -m unittest tools.test_gen_event_profile
"""
import os
import subprocess
import sys
import tempfile
import unittest

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TOOLS_DIR)

sys.path.insert(0, TOOLS_DIR)
import gen_event_profile as gep  # noqa: E402

SCRIPT = os.path.join(TOOLS_DIR, "gen_event_profile.py")
TEMPLATE = os.path.join(REPO_ROOT, "include", "event_profile.h.in")

# BIP-340 test vector 0 (privkey=3) -- the same fixed, published, never-real
# key tools/pipeline_test/Makefile uses for its own host-test event_profile.h.
TEST_PRIVKEY_HEX = (
    "0000000000000000000000000000000000000000000000000000000000000003"
)


class NormalizeEventNameTests(unittest.TestCase):
    """In-process tests of normalize_event_name() -- accept/reject/fold/length."""

    def test_accepts_plain_uppercase(self):
        self.assertEqual(gep.normalize_event_name("SUMMER JAM"), "SUMMER JAM")

    def test_accepts_digits_and_spaces(self):
        self.assertEqual(gep.normalize_event_name("JAM 2026"), "JAM 2026")

    def test_folds_lowercase_to_uppercase(self):
        self.assertEqual(gep.normalize_event_name("summer jam"), "SUMMER JAM")

    def test_folds_mixed_case(self):
        self.assertEqual(gep.normalize_event_name("Summer Jam 2026"), "SUMMER JAM 2026")

    def test_accepts_exactly_15_chars(self):
        name = "SUMMER JAM 2026"  # exactly 15 chars
        self.assertEqual(len(name), 15)
        self.assertEqual(gep.normalize_event_name(name), name)

    def test_rejects_16_chars_not_truncated(self):
        name = "SUMMER JAM 20266"  # 16 chars, one over the cap
        self.assertEqual(len(name), 16)
        with self.assertRaises(ValueError) as ctx:
            gep.normalize_event_name(name)
        msg = str(ctx.exception)
        self.assertIn("16", msg)
        self.assertIn("15", msg)
        # Never truncated: the original, untruncated value is quoted back.
        self.assertIn(name, msg)

    def test_rejects_16_chars_after_folding(self):
        # Folding never changes length, but confirm the cap is enforced on
        # the FOLDED string, not just the raw input length.
        name = "summer jam 20266"
        with self.assertRaises(ValueError):
            gep.normalize_event_name(name)

    def test_rejects_out_of_charset_character_and_names_it(self):
        with self.assertRaises(ValueError) as ctx:
            gep.normalize_event_name("SUMMER JAM!")
        self.assertIn("!", str(ctx.exception))

    def test_rejects_punctuation_after_fold(self):
        with self.assertRaises(ValueError) as ctx:
            gep.normalize_event_name("Jam-2026")
        self.assertIn("-", str(ctx.exception))

    def test_rejects_unicode_letter_never_silently_dropped(self):
        with self.assertRaises(ValueError) as ctx:
            gep.normalize_event_name("CAFEÉ")  # trailing E-acute
        self.assertIn("É", str(ctx.exception))

    def test_rejects_empty_string(self):
        with self.assertRaises(ValueError):
            gep.normalize_event_name("")

    def test_rejects_none(self):
        with self.assertRaises(ValueError):
            gep.normalize_event_name(None)

    def test_rejects_all_whitespace(self):
        # Space is a legal char, but an all-space name states nothing --
        # matches the Makefile's own $(strip ...) emptiness gate.
        with self.assertRaises(ValueError):
            gep.normalize_event_name("   ")

    def test_rejects_newline(self):
        # Regression guard: a naive per-character `^[A-Z0-9 ]*$` regex match
        # wrongly accepts "\n" because `$` matches just before a trailing
        # newline even with the `*` (zero-width) branch. A newline baked
        # verbatim into a C string literal is exactly the "garbled ROM"
        # #76 exists to prevent.
        with self.assertRaises(ValueError) as ctx:
            gep.normalize_event_name("A\nB")
        self.assertIn(repr("\n"), str(ctx.exception))

    def test_rejects_bare_newline(self):
        with self.assertRaises(ValueError):
            gep.normalize_event_name("\n")

    def test_rejects_tab(self):
        with self.assertRaises(ValueError):
            gep.normalize_event_name("A\tB")

    def test_rejects_carriage_return(self):
        with self.assertRaises(ValueError):
            gep.normalize_event_name("A\rB")

    def test_rejects_null_byte(self):
        with self.assertRaises(ValueError):
            gep.normalize_event_name("A\x00B")

    def test_rejects_double_quote(self):
        # Not embedded raw into a C string literal like --tag is, but still
        # outside the allowed charset -- must be rejected all the same.
        with self.assertRaises(ValueError):
            gep.normalize_event_name('A"B')

    def test_accepts_all_spaces_within_cap(self):
        # Spaces are legal, one slot each -- not silently collapsed/stripped.
        self.assertEqual(gep.normalize_event_name("A B"), "A B")

    def test_does_not_strip_or_collapse_interior_spaces(self):
        self.assertEqual(gep.normalize_event_name("A  B"), "A  B")


class GenEventProfileCliTests(unittest.TestCase):
    """End-to-end CLI tests: subprocess-invoke the real script, exactly as
    the Makefile does, and assert on exit code / stderr / emitted header."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="gen_event_profile_test_")
        self.privkey_path = os.path.join(self.tmpdir, "event_privkey.hex")
        with open(self.privkey_path, "w") as f:
            f.write(TEST_PRIVKEY_HEX + "\n")
        self.out_path = os.path.join(self.tmpdir, "event_profile.h")
        self.manifest_path = os.path.join(self.tmpdir, "event_profile.manifest.json")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def run_script(self, extra_args):
        cmd = [
            sys.executable,
            SCRIPT,
            "--privkey", self.privkey_path,
            "--template", TEMPLATE,
            "--out", self.out_path,
            "--label", "test-label",
            "--manifest", self.manifest_path,
            "--commit", "deadbeef",
            "--created-at", "1700000000",
        ] + extra_args
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_missing_event_name_flag_fails_closed(self):
        # No --event-name at all: argparse itself refuses (required=True),
        # mirroring --privkey/--template/--out/--label/--manifest's own
        # required=True fail-closed shape.
        result = self.run_script([])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--event-name", result.stderr)
        self.assertFalse(os.path.exists(self.out_path))

    def test_empty_event_name_is_fatal(self):
        result = self.run_script(["--event-name", ""])
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL", result.stderr)
        self.assertFalse(os.path.exists(self.out_path))

    def test_whitespace_only_event_name_is_fatal(self):
        result = self.run_script(["--event-name", "   "])
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL", result.stderr)
        self.assertFalse(os.path.exists(self.out_path))

    def test_invalid_charset_is_fatal_and_names_the_character(self):
        result = self.run_script(["--event-name", "JAM!"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL", result.stderr)
        self.assertIn("!", result.stderr)
        self.assertFalse(os.path.exists(self.out_path))

    def test_overlong_event_name_is_fatal_not_truncated(self):
        result = self.run_script(["--event-name", "THIS NAME IS WAY TOO LONG"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL", result.stderr)
        self.assertFalse(os.path.exists(self.out_path))

    def test_valid_event_name_emits_header_defines(self):
        name = "summer jam 2026"
        self.assertEqual(len(name), 15)  # exercise the exact-cap boundary
        result = self.run_script(["--event-name", name])
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.out_path) as f:
            header = f.read()
        self.assertIn('#define PIPELINE_EVENT_NAME "SUMMER JAM 2026"', header)
        self.assertIn(
            "#define PIPELINE_EVENT_NAME_LEN (sizeof(PIPELINE_EVENT_NAME) - 1)",
            header,
        )

    def test_valid_event_name_folds_and_bounds_exactly(self):
        result = self.run_script(["--event-name", "arcade night"])
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.out_path) as f:
            header = f.read()
        self.assertIn('#define PIPELINE_EVENT_NAME "ARCADE NIGHT"', header)

    def test_event_name_kept_separate_from_label_and_tag(self):
        result = self.run_script(
            ["--event-name", "ARCADE NIGHT", "--tag", "sm64"]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.out_path) as f:
            header = f.read()
        # The event name and the per-game tag are baked as two distinct
        # macros with two distinct values -- never conflated.
        self.assertIn('#define PIPELINE_EVENT_NAME "ARCADE NIGHT"', header)
        self.assertIn('#define PIPELINE_EVENT_TAG_1_VALUE "sm64"', header)
        with open(self.manifest_path) as f:
            manifest_text = f.read()
        self.assertIn('"event_name": "ARCADE NIGHT"', manifest_text)
        self.assertIn('"label": "test-label"', manifest_text)

    def test_event_name_absent_from_format_descriptor_wire_fields(self):
        # The emitted header must define PIPELINE_EVENT_NAME (display-only)
        # but the wire-relevant macros (TAG_1, pubkey, created_at) must be
        # unaffected by / independent of it.
        result = self.run_script(["--event-name", "ARCADE NIGHT"])
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.out_path) as f:
            header = f.read()
        self.assertIn("PIPELINE_EVENT_PUBKEY_HEX", header)
        self.assertIn("PIPELINE_EVENT_TAG_1_VALUE", header)
        self.assertIn("PIPELINE_EVENT_NAME", header)


class EventNameOffWireTests(unittest.TestCase):
    """Static off-wire checks (spec #75, sub-issue #76): PIPELINE_EVENT_NAME
    must never be sourced by build_event()'s pack stage or reach the packed
    payload / signed NIP-01 event. Since this is a structural invariant
    (an absence), assert it directly against the actual pipeline sources
    rather than only against gen_event_profile.py's own behavior above."""

    PACK_STAGE_FILES = [
        os.path.join(REPO_ROOT, "src", "pipeline", "build_event.c"),
        os.path.join(REPO_ROOT, "src", "pipeline", "build_event.h"),
        os.path.join(REPO_ROOT, "src", "pipeline", "pack_adapter.c"),
        os.path.join(REPO_ROOT, "src", "pipeline", "pack_adapter.h"),
        os.path.join(REPO_ROOT, "src", "pipeline", "event_id.c"),
        os.path.join(REPO_ROOT, "src", "pipeline", "event_id.h"),
    ]

    def test_pipeline_event_name_not_referenced_by_pack_stage(self):
        for path in self.PACK_STAGE_FILES:
            if not os.path.exists(path):
                continue  # tolerate future file moves; other files still checked
            with open(path, "r") as f:
                contents = f.read()
            self.assertNotIn(
                "PIPELINE_EVENT_NAME",
                contents,
                "%s must never reference PIPELINE_EVENT_NAME -- the event "
                "name is display-only and must never reach the packed QR "
                "payload or the signed NIP-01 event (spec #75, sub-issue #76)"
                % path,
            )

    def test_template_documents_the_honesty_invariant(self):
        with open(TEMPLATE, "r") as f:
            contents = f.read()
        self.assertIn("PIPELINE_EVENT_NAME", contents)
        self.assertIn("DISPLAY-ONLY", contents.upper())
        self.assertIn("AIRGAPPED HONESTY INVARIANT", contents)


class MakefileFailClosedStaticTests(unittest.TestCase):
    """Static sanity-check of the Makefile's fail-closed gate for
    PIPELINE_EVENT_NAME (spec #75, sub-issue #76). `make` itself is not
    available in this environment (no MIPS/host make toolchain here), so
    this asserts the $(error ...) gate text and structure directly rather
    than by actually invoking make; the real build environment (the Docker
    build wizard) is where the live `make` fail-closed path executes."""

    def setUp(self):
        makefile_path = os.path.join(REPO_ROOT, "Makefile")
        with open(makefile_path, "r", encoding="utf-8") as f:
            self.makefile_text = f.read()

    def test_has_error_directive_for_empty_event_name(self):
        self.assertIn("PIPELINE_EVENT_NAME", self.makefile_text)
        self.assertIn(
            "ifeq ($(strip $(PIPELINE_EVENT_NAME)),)", self.makefile_text
        )
        self.assertIn(
            "$(error PIPELINE_EVENT_NAME is unset/empty", self.makefile_text
        )

    def test_event_name_check_exempts_the_same_goals_as_the_privkey_check(self):
        # Mirrors PIPELINE_PRIVKEY_FILE's own fail-closed check: both must
        # skip the same non-ROM-building goals (clean/distclean/print-%/
        # pipeline-test), so `make clean` etc. never require an event name.
        expected_filter = "$(filter clean distclean print-% pipeline-test,$(MAKECMDGOALS))"
        occurrences = self.makefile_text.count(expected_filter)
        self.assertGreaterEqual(
            occurrences,
            2,
            "expected the PIPELINE_EVENT_NAME check to reuse the identical "
            "exemption filter as the PIPELINE_PRIVKEY_FILE check",
        )

    def test_recipe_passes_event_name_flag_to_the_generator(self):
        self.assertIn('--event-name "$(PIPELINE_EVENT_NAME)"', self.makefile_text)


class BuildWizardStaticTests(unittest.TestCase):
    """Static check that build.ps1 (the one blessed build path, per
    docs/adr/0003) actually requires and threads -EventName through to
    `make PIPELINE_EVENT_NAME=...` -- #76 making PIPELINE_EVENT_NAME
    required must not silently break the wizard's `make` invocation."""

    def setUp(self):
        with open(os.path.join(REPO_ROOT, "build.ps1"), "r", encoding="utf-8") as f:
            self.wizard_text = f.read()

    def test_event_name_param_exists(self):
        self.assertIn("[string]$EventName,", self.wizard_text)

    def test_fails_closed_when_event_name_missing(self):
        self.assertIn("No -EventName supplied", self.wizard_text)

    def test_threads_event_name_into_make_invocation(self):
        self.assertIn("PIPELINE_EVENT_NAME=", self.wizard_text)
        self.assertIn("$shSafeEventName", self.wizard_text)


if __name__ == "__main__":
    unittest.main()
