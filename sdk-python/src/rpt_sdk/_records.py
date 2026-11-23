"""The record wire types.

Each matches its schema in rpt's ``schema/`` folder: members the type doesn't name ride in
``extra``, so records pass through with fields this version doesn't know. Decoding is
lenient, as rpt's own is: a missing member takes its empty value. Encoding leaves out empty
optional members, always writes required ones, and writes the record's kind when ``kind`` is
empty, so ``Finding(title="t", severity="high")`` is a whole finding record.
"""

from __future__ import annotations

import dataclasses
import types
import typing
from dataclasses import dataclass, field
from typing import Any, ClassVar, TypeVar, Union

from ._stream import strict_loads

W = TypeVar("W", bound="Wire")

#: Field metadata for a member every record of the type has, written even when empty.
_REQUIRED = {"required": True}


def _req(default: Any = "") -> Any:
    if isinstance(default, (list, dict)):
        return field(default_factory=type(default), metadata=_REQUIRED)
    return field(default=default, metadata=_REQUIRED)


def _list() -> Any:
    return field(default_factory=list)


def _dict() -> Any:
    return field(default_factory=dict)


_HINTS: dict[type, dict[str, Any]] = {}


def _hints(cls: type) -> dict[str, Any]:
    if cls not in _HINTS:
        _HINTS[cls] = typing.get_type_hints(cls)
    return _HINTS[cls]


def _optional(tp: Any) -> Any | None:
    """For ``X | None``, X; otherwise None."""
    if typing.get_origin(tp) in (Union, types.UnionType):
        args = [a for a in typing.get_args(tp) if a is not type(None)]
        if len(args) == 1:
            return args[0]
    return None


def _decode(tp: Any, v: Any, where: str) -> Any:
    inner = _optional(tp)
    if inner is not None:
        return None if v is None else _decode(inner, v, where)
    if tp is Any:
        return v
    if isinstance(tp, type) and issubclass(tp, Wire):
        return tp.from_dict(v)
    origin = typing.get_origin(tp)
    if origin is list:
        if not isinstance(v, list):
            raise ValueError(f"{where}: got {type(v).__name__}, want a list")
        (item,) = typing.get_args(tp)
        return [_decode(item, x, where) for x in v]
    if origin is dict:
        if not isinstance(v, dict):
            raise ValueError(f"{where}: got {type(v).__name__}, want an object")
        _, item = typing.get_args(tp)
        return {k: _decode(item, x, f"{where}.{k}") for k, x in v.items()}
    if tp is int and (isinstance(v, bool) or not isinstance(v, int)):
        raise ValueError(f"{where}: got {v!r}, want an integer")
    if tp in (str, bool) and not isinstance(v, tp):
        raise ValueError(f"{where}: got {v!r}, want a {tp.__name__}")
    return v


def _encode(v: Any) -> Any:
    if isinstance(v, Wire):
        return v.to_dict()
    if isinstance(v, list):
        return [_encode(x) for x in v]
    if isinstance(v, dict):
        return {k: _encode(x) for k, x in v.items()}
    return v


@dataclass(kw_only=True)
class Wire:
    """Base of the wire types: decoding, encoding and unknown members."""

    #: Every member the type doesn't name, kept so records pass through whole.
    extra: dict[str, Any] = field(default_factory=dict)

    #: The kind a record type writes when ``kind`` is empty; empty for parts of records.
    KIND: ClassVar[str] = ""

    @classmethod
    def from_dict(cls: type[W], data: Any) -> W:
        """Decodes a record from its JSON object, already parsed."""
        if not isinstance(data, dict):
            raise ValueError(f"{cls.__name__}: got {type(data).__name__}, want an object")
        hints = _hints(cls)
        names = {f.name for f in dataclasses.fields(cls)} - {"extra"}
        known: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        for name, value in data.items():
            if name not in names:
                extra[name] = value
            elif value is not None or _optional(hints[name]) is not None:
                known[name] = _decode(hints[name], value, f"{cls.__name__}.{name}")
        return cls(**known, extra=extra)

    @classmethod
    def from_json(cls: type[W], raw: bytes | str) -> W:
        """Decodes a record from its text, such as :attr:`Rec.raw`."""
        return cls.from_dict(strict_loads(raw))

    def to_dict(self) -> dict[str, Any]:
        """The record as a JSON object, as :func:`emit` writes it."""
        hints = _hints(type(self))
        out: dict[str, Any] = {}
        for f in dataclasses.fields(self):
            if f.name == "extra":
                continue
            v = getattr(self, f.name)
            if f.name == "kind" and not v:
                v = self.KIND
            if not f.metadata.get("required"):
                if v is None or (_optional(hints[f.name]) is None and not v):
                    continue
            out[f.name] = _encode(v)
        for name, value in self.extra.items():
            out.setdefault(name, value)
        return out


# The record kinds rpt reads and writes. A plugin's own kinds are x-<plugin>[-<name>].
KIND_FINDING = "finding"
KIND_PAGE = "page"
KIND_SCOPE = "scope"
KIND_CONFIG = "config"
KIND_EVIDENCE = "evidence"
KIND_PROBLEM = "problem"
KIND_REPORT = "report"
KIND_LOCATION = "location"
KIND_COMMAND = "command"
KIND_VERSION = "version"

# The severity levels rpt knows by default. The order of levels is set by the report's config.
CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

# The problem levels. An error makes rpt validate exit 1.
ERROR = "error"
WARNING = "warning"

# The sources of a reference to a file, Asset.source.
SOURCE_FRONTMATTER = "frontmatter"  # the evidence list
SOURCE_BODY = "body"  # a link in the text

# The roles a plugin can declare in Description.roles. Each is a promise the protocol's
# --describe section spells out.
ROLE_CHECKER = "checker"  # emits problems about the report; exits 1 only on an error; never changes it
ROLE_FILTER = "filter"  # reads records on stdin and writes records on stdout
ROLE_WRITER = "writer"  # changes the report, only through $RPT_BIN write commands
ROLE_RENDERER = "renderer"  # writes a document from a report record; no records to stdout


@dataclass(kw_only=True)
class Position(Wire):
    """A place in a file: a 1-based line, and the 1-based byte in that line."""

    line: int = _req(0)
    column: int = _req(0)


@dataclass(kw_only=True)
class SectionLines(Wire):
    """Where one section sits in a finding file. Line ``text + n`` is line n+1 of the
    section's text."""

    heading: int = _req(0)
    #: The text's first line; 0 when the section is empty.
    text: int = 0


@dataclass(kw_only=True)
class Lines(Wire):
    """Where a record's parts sit in its file, as ``--lines`` gives them: 1-based lines of the
    file as stored, so a checker can place a problem without parsing the file itself."""

    #: The file's absolute path, symlinks kept.
    file: str = ""
    #: Frontmatter or rpt.yaml top-level keys.
    keys: dict[str, Position] = _dict()
    #: A finding's sections, keyed like Finding.sections.
    sections: dict[str, SectionLines] = _dict()
    #: The line a page's body starts on.
    body: int = 0
    #: The line a scope row starts on.
    row: int = 0


@dataclass(kw_only=True)
class ScopeRow(Wire):
    """A ``scope`` record: one in-scope asset, a row of scope.csv. ``extra`` holds the row's
    other columns."""

    KIND: ClassVar[str] = KIND_SCOPE
    kind: str = _req()
    id: str = _req()
    host: str = _req()
    #: 0: every port.
    port: int = 0
    #: ``tcp`` or ``udp``; empty: any.
    protocol: str = ""
    #: The row's revision, over the header and the row's own text.
    rev: str = ""
    lines: Lines | None = None


@dataclass(kw_only=True)
class Target(Wire):
    """One place a finding was found on, attributed to a scope row. ``scope`` names the row's
    ID; ``host`` is set only when the row is a range (a CIDR or ``*.domain``).

    A parser plugin, which doesn't know the report's scope, sets ``host`` (and ``port`` and
    ``protocol``) and leaves ``scope`` empty; ``rpt scope match`` fills it.
    """

    scope: str = ""
    #: The row itself, in an assembled report.
    row: ScopeRow | None = None
    host: str = ""
    port: int = 0
    #: ``tcp`` or ``udp``.
    protocol: str = ""


@dataclass(kw_only=True)
class Asset(Wire):
    """One file a finding or page lists in its evidence or links in its text."""

    #: As the owner writes it, relative to its file.
    ref: str = ""
    #: Relative to the report root; empty when ref leaves the report.
    path: str = ""
    #: Absolute, symlinks kept: the file to open or copy.
    file: str = ""
    #: SOURCE_FRONTMATTER or SOURCE_BODY.
    source: str = ""
    #: The file's type, from its extension, else its content.
    media_type: str = ""
    #: A link's text, its caption.
    text: str = ""
    #: The link is an image.
    image: bool = False


@dataclass(kw_only=True)
class Finding(Wire):
    """A ``finding`` record: one finding, as ``rpt finding get``, parser plugins and
    ``rpt assemble`` give it."""

    KIND: ClassVar[str] = KIND_FINDING
    kind: str = _req()
    id: str = ""
    title: str = _req()
    #: The scope rows it was found on.
    targets: list[Target] = _req([])
    severity: str = _req()
    #: Relative to the report root.
    path: str = ""
    #: The file's revision; pass it back as --if-rev.
    rev: str = ""
    sections: dict[str, str] = _dict()
    #: Relative to the finding file's folder.
    evidence: list[str] = _list()
    #: Set by --lines; rpt finding add ignores it.
    lines: Lines | None = None
    #: The files it lists and links, set by --assets and by rpt assemble. rpt finding add reads
    #: each one's ref and file: it copies the file in and points ref at the copy.
    assets: list[Asset] = _list()


@dataclass(kw_only=True)
class Page(Wire):
    """A ``page`` record: one page of report-level prose, such as an executive summary."""

    KIND: ClassVar[str] = KIND_PAGE
    kind: str = _req()
    id: str = _req()
    title: str = _req()
    path: str = ""
    #: Markdown; ## headings in it are the page's own.
    body: str = _req()
    evidence: list[str] = _list()
    rev: str = ""
    lines: Lines | None = None
    assets: list[Asset] = _list()


@dataclass(kw_only=True)
class Config(Wire):
    """A ``config`` record: rpt.yaml as in effect, defaults filled in. Plugin sections
    (``x-<plugin>``) are in ``extra``."""

    KIND: ClassVar[str] = KIND_CONFIG
    kind: str = _req()
    format: int = 0
    #: Most severe first.
    severities: list[str] = _list()
    #: Fixed section key to its heading.
    sections: dict[str, str] = _dict()
    #: Section keys, or a custom section's heading.
    required_sections: list[str] = _list()
    #: Rule name to the level its problems take.
    rules: dict[str, str] = _dict()
    #: Page IDs, and "findings" where the findings go.
    pages: list[str] = _list()
    required_pages: list[str] = _list()
    rev: str = ""
    lines: Lines | None = None


@dataclass(kw_only=True)
class Evidence(Asset):
    """An ``evidence`` record ``rpt evidence get`` emits: one reference a finding or page
    makes to a file, or with --orphans a file nothing references (no owner, ref or source)."""

    KIND: ClassVar[str] = KIND_EVIDENCE
    kind: str = _req()
    #: The owner, when a finding.
    finding: str = ""
    #: The owner, when a page.
    page: str = ""
    exists: bool = _req(False)
    #: The finding section a link is in.
    section: str = ""
    #: Where the reference is in the owner's file.
    line: int = 0
    #: The owner's rev.
    rev: str = ""


@dataclass(kw_only=True)
class Problem(Wire):
    """A ``problem`` record: one broken rule that rpt or a checker plugin found."""

    KIND: ClassVar[str] = KIND_PROBLEM
    kind: str = _req()
    #: Relative to the report root; "-" for stdin.
    path: str = _req()
    #: 1-based; 0 when the problem has no line.
    line: int = 0
    #: 1-based byte in the line; only with line.
    column: int = 0
    rule: str = _req()
    #: ERROR or WARNING.
    level: str = _req()
    message: str = _req()
    #: The command that found it; never changed downstream.
    command: str = ""
    #: Replacements for the text the problem is about, best first.
    suggestions: list[str] = _list()
    #: The 1-based byte, inclusive, the text the suggestions replace ends at.
    end_column: int = 0
    #: The rev of the file the problem is in, as read.
    rev: str = ""

    def is_error(self) -> bool:
        """Whether it is error-level: a writer or renderer reading it stops."""
        return self.level == ERROR


@dataclass(kw_only=True)
class Section(Wire):
    """One finding section: the key a finding's sections use and the heading this report
    gives it."""

    key: str = _req()
    heading: str = _req()


@dataclass(kw_only=True)
class Report(Wire):
    """The ``report`` record ``rpt assemble`` emits: the whole render-ready report."""

    KIND: ClassVar[str] = KIND_REPORT
    kind: str = _req()
    schema_version: int = _req(0)
    #: Most severe first.
    severities: list[str] = _req([])
    #: The fixed sections with this report's headings, then the custom ones it requires.
    sections: list[Section] = _req([])
    #: Page IDs, and "findings" where the findings go, in reading order.
    order: list[str] = _req([])
    #: Finding count per level.
    summary: dict[str, int] = _req({})
    scope: list[ScopeRow] = _req([])
    #: By severity, then ID.
    findings: list[Finding] = _req([])
    #: In order.
    pages: list[Page] = _req([])


@dataclass(kw_only=True)
class Location(Wire):
    """A ``location`` record ``rpt ls`` emits: a report found. ``format`` and ``findings``
    are None when its config doesn't parse."""

    KIND: ClassVar[str] = KIND_LOCATION
    kind: str = _req()
    #: Absolute.
    path: str = _req()
    format: int | None = None
    #: Finding files that parse.
    findings: int | None = None


@dataclass(kw_only=True)
class Version(Wire):
    """The ``version`` record ``rpt version`` emits."""

    KIND: ClassVar[str] = KIND_VERSION
    kind: str = _req()
    #: Release tag, module version, or "dev".
    version: str = _req()
    #: Record schemas this rpt writes.
    schema_version: int = _req(0)
    #: Report format this rpt reads.
    format: int = _req(0)


@dataclass(kw_only=True)
class Range(Wire):
    """The versions from ``min`` to ``max``, both included. A bound left 0 is open, so
    ``Range(min=2)`` fits 2 and every later version."""

    min: int = 0
    max: int = 0

    def has(self, v: int) -> bool:
        """Whether ``v`` is in the range."""
        return (self.min == 0 or v >= self.min) and (self.max == 0 or v <= self.max)

    def __str__(self) -> str:
        """The range for people: "2", "2 to 3", "2 or later", "up to 1", or "any"."""
        if self.min == 0 and self.max == 0:
            return "any"
        if self.max == 0:
            return f"{self.min} or later"
        if self.min == 0:
            return f"up to {self.max}"
        if self.min == self.max:
            return str(self.min)
        return f"{self.min} to {self.max}"


@dataclass(kw_only=True)
class Requires(Wire):
    """The rpt versions a plugin works with, each as a range. A range left out fits any
    version."""

    #: Record schemas, Version.schema_version.
    schema_version: Range | None = None
    #: Report format, Version.format.
    format: Range | None = None

    def fits(self, schema_version: int, format: int) -> bool:
        """Whether a plugin requiring this works with an rpt writing ``schema_version`` and
        reading ``format``."""
        return (self.schema_version is None or self.schema_version.has(schema_version)) and (
            self.format is None or self.format.has(format)
        )


@dataclass(kw_only=True)
class Schemas(Wire):
    """The JSON Schemas (draft 2020-12) a plugin declares for what it owns, by noun. A plugin
    named <command> owns ``x-<command>`` and the names starting ``x-<command>-``."""

    #: Each frontmatter key the plugin owns, to a schema for its value.
    finding: dict[str, Any] = _dict()
    page: dict[str, Any] = _dict()
    #: Each scope column; a scope value is the CSV text.
    scope: dict[str, Any] = _dict()
    #: The schema for the plugin's whole x-<command> section of rpt.yaml.
    config: Any = None
    #: Each x- record kind, to a schema for the whole record.
    kinds: dict[str, Any] = _dict()


@dataclass(kw_only=True)
class Description(Wire):
    """What a plugin prints for ``--describe``: one JSON object on one line. The plugin's name
    comes from its file name (``rpt-parse-nuclei`` is the command ``parse-nuclei``)."""

    #: One line: what the plugin does.
    summary: str = _req()
    #: One line, e.g. "rpt parse-nuclei < results.jsonl"; name the plugin's flags.
    usage: str = ""
    #: The plugin's own version.
    version: str = ""
    #: "records" for an rpt JSON Lines stream, otherwise "<format>" or "<format>/<tool>".
    input: str = ""
    output: str = ""
    #: ROLE_CHECKER, ROLE_FILTER, ROLE_WRITER, ROLE_RENDERER; empty is "not said".
    roles: list[str] = _list()
    schemas: Schemas | None = None
    requires: Requires | None = None


@dataclass(kw_only=True)
class Command(Description):
    """A ``command`` record ``rpt help`` emits: something ``rpt <name>`` can run, a built-in
    or a plugin, with what its ``--describe`` answer says."""

    KIND: ClassVar[str] = KIND_COMMAND
    kind: str = _req()
    name: str = _req()
    #: "builtin" or "plugin".
    source: str = _req()
    #: A plugin's absolute path.
    path: str = ""
    #: A plugin a built-in of the same name hides.
    shadowed: bool = False
    #: A plugin whose requires this rpt doesn't fit.
    incompatible: bool = False
