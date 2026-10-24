"""Render evaluation results to Markdown and HTML with Jinja2 (HTML is autoescaped)."""

from __future__ import annotations

import json
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from .crosswalk import Crosswalk
from .library import Library
from .model import ControlResult, EvaluationRun

DISCLAIMER = (
    "This package supports a SOC 2 examination; it is not one. It is not an audit opinion, a "
    "SOC 2 report or an attestation. Automated checks only test the evidence they were given at "
    "a point in time. The service auditor decides whether evidence is sufficient, tests "
    "operating effectiveness over the examination period, and forms the opinion."
)


def _md_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _annex(ids: list[str]) -> str:
    return ", ".join(f"A.{i}" for i in ids)


def environment() -> Environment:
    env = Environment(
        loader=PackageLoader("controlmap", "templates"),
        autoescape=select_autoescape(enabled_extensions=("html.j2",), default=False),
        undefined=StrictUndefined,
        trim_blocks=False,
        lstrip_blocks=False,
        keep_trailing_newline=True,
    )
    env.filters["md"] = _md_cell
    env.filters["annex"] = _annex
    return env


class Renderer:
    def __init__(self, library: Library, run: EvaluationRun, crosswalk: Crosswalk) -> None:
        self.library = library
        self.run = run
        self.crosswalk = crosswalk
        self.env = environment()
        loader = self.env.loader
        assert loader is not None
        self.css = loader.get_source(self.env, "style.css")[0]

    def _control_view(self, result: ControlResult) -> dict[str, Any]:
        control = self.library.control(result.control_id)
        catalogs = self.library.catalogs
        view = result.to_dict()
        view["description"] = control.description
        view["tsc"] = [{"id": t, "label": catalogs.tsc[t].label} for t in result.tsc]
        view["iso"] = [{"id": i, "title": catalogs.iso[i].title} for i in result.iso]
        view["tsc_ids"] = list(result.tsc)
        view["iso_ids"] = [f"A.{i}" for i in result.iso]
        for rule in view["rules"]:
            rule["params_text"] = json.dumps(rule["params"], sort_keys=True)
        return view

    def _common(self, generated_at: str) -> dict[str, Any]:
        return {
            "company": self.run.company,
            "as_of": self.run.as_of.isoformat(),
            "generated_at": generated_at,
            "disclaimer": DISCLAIMER,
            "css": self.css,
        }

    def control_pages(self, generated_at: str) -> dict[str, str]:
        pages: dict[str, str] = {}
        html = self.env.get_template("control.html.j2")
        md = self.env.get_template("control.md.j2")
        for result in self.run.controls:
            context = {**self._common(generated_at), "c": self._control_view(result)}
            pages[f"controls/{result.control_id}.html"] = html.render(context)
            pages[f"controls/{result.control_id}.md"] = md.render(context)
        return pages

    def overview_pages(
        self, generated_at: str, tool_version: str, signed: bool, fingerprint: str | None
    ) -> dict[str, str]:
        crosswalk = self.crosswalk.to_dict()
        context = {
            **self._common(generated_at),
            "tool_version": tool_version,
            "counts": self.run.counts(),
            "controls": [self._control_view(c) for c in self.run.controls],
            "coverage": crosswalk["coverage"],
            "criteria": crosswalk["criteria"],
            "iso": crosswalk["iso27001"],
            "exceptions": self.run.exception_report["entries"],
            "signed": signed,
            "fingerprint": fingerprint or "",
        }
        return {
            "index.html": self.env.get_template("index.html.j2").render(context),
            "summary.md": self.env.get_template("summary.md.j2").render(context),
            "crosswalk.md": self.env.get_template("crosswalk.md.j2").render(context),
            "exceptions.md": self.env.get_template("exceptions.md.j2").render(context),
        }
