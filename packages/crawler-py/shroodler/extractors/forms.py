from __future__ import annotations

from bs4 import BeautifulSoup, Tag

from shroodler.models import Finding, Form, FormField

_INPUT_TYPES = {
    "text",
    "password",
    "hidden",
    "checkbox",
    "radio",
    "file",
    "email",
    "search",
    "number",
    "submit",
    "button",
    "reset",
}


def _field_from_tag(tag: Tag) -> FormField | None:
    name = tag.get("name")
    if not name:
        return None
    tag_name = tag.name.lower()
    if tag_name == "select":
        ftype = "select"
    elif tag_name == "textarea":
        ftype = "textarea"
    else:
        ftype = (tag.get("type") or "text").lower()
    hidden = ftype == "hidden" or tag.has_attr("hidden")
    return FormField(
        name=str(name),
        type=ftype,
        hidden=hidden,
        disabled=tag.has_attr("disabled") or None,
        readonly=tag.has_attr("readonly") or None,
    )


def extract_forms(html: str, page_url: str) -> tuple[list[Form], list[Finding]]:
    soup = BeautifulSoup(html, "lxml")
    forms: list[Form] = []
    findings: list[Finding] = []
    for form in soup.find_all("form"):
        action = form.get("action")
        action_s = str(action) if action is not None else ""
        method = (form.get("method") or "GET").upper()
        enctype = form.get("enctype")
        fields: list[FormField] = []
        for tag in form.find_all(["input", "select", "textarea"]):
            field = _field_from_tag(tag)
            if field:
                fields.append(field)
                if field.type == "password":
                    ac = (tag.get("autocomplete") or "").lower()
                    if ac in {"on", "current-password", "new-password"} or ac == "":
                        if ac == "on":
                            findings.append(
                                Finding(
                                    id="autocomplete",
                                    severity="low",
                                    category="autocomplete",
                                    url=page_url,
                                    description="Password field allows autocomplete",
                                    evidence=field.name,
                                )
                            )
        forms.append(
            Form(
                action=action_s,
                method=method,
                fields=fields,
                enctype=str(enctype) if enctype else None,
            )
        )
    return forms, findings
