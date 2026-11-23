#!/usr/bin/env python3
"""Render the static app with synthetic API responses. Requires Python Playwright and Chromium.

From web after npm run build:static:
    python3 scripts/investigation-browser.py --static out
Pass --live-only and a pinned baseline build to exercise the original Authority UI.
"""
import argparse
import asyncio
import hashlib
import json
import re
import shutil
import tempfile
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from playwright.async_api import async_playwright, expect

STAMP = "2026-11-20T00:00:00Z"
TOKEN = "browser-fixture"
COVERAGE = "recorded_interception_decisions"


class StaticFiles(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass


def record(task, number):
    return {
        "task_id": task, "id": number, "tool_name": f"fixture-{task}-tool-{number}",
        "agent_name": "synthetic observer", "decision_source": "model", "decided_by": "human",
        "audit_present": True, "status": "allowed", "correlation": "exact", "run_id": "run-1",
        "tool_use_id": f"call-{number}", "execution_status": "succeeded", "rule_name": "",
        "created_at": STAMP, "decided_at": STAMP, "execution_ended_at": STAMP,
        "input_digest": "", "config_digest": "", "model_input_digest": "",
        "initial_action": "ask", "effective_action": "ask",
    }


class Fixture:
    def __init__(self, origin):
        self.origin = origin
        self.authority_reads = 0
        self.requests = []
        self.violations = []
        self.held = None
        self.release = asyncio.Event()
        self.started = asyncio.Event()
        self.released = asyncio.Event()
        self.fail_refresh = False
        self.shrunk = False
        self.wrong_source = False
        self.case_bytes = None
        self.source_request = None
        self.source_ok = False

    async def respond(self, route):
        request = route.request
        url = urlparse(request.url)
        path = url.path
        if f"{url.scheme}://{url.netloc}" != self.origin:
            self.violations.append(("outside fixture", request.method, path))
            return await route.abort()
        if not path.startswith("/api/"):
            return await route.continue_()
        query = parse_qs(url.query)
        self.requests.append((request.method, path))
        frame_path = urlparse(request.frame.url).path.rstrip("/")
        if frame_path == "/function/investigation" and path == "/api/intercept/pending":
            self.violations.append(("live approval read on standalone casefile page", request.method, path))
            return await route.abort()
        if self.source_request and (request.method, path) == ("POST", self.source_request[0]):
            assert request.headers.get("authorization") == f"Bearer {TOKEN}"
            assert request.post_data_json == self.source_request[1]
            if not self.source_ok:
                return await route.fulfill(status=409, json={"error": "exact source unavailable"})
            self.source_request = None
            return await route.fulfill(json={"task_id": path.split("/")[3], "session": "main:0", "seq": 32})
        if request.method != "GET" or path.startswith("/api/traffic/replay"):
            self.violations.append(("unexpected API", request.method, path))
            return await route.abort()

        task = re.fullmatch(r"/api/tasks/(\d+)", path)
        authority = re.fullmatch(r"/api/tasks/(\d+)/authority", path)
        if task:
            result = {"id": task[1], "status": "done", "name": f"Synthetic task {task[1]}"}
        elif authority:
            assert request.headers.get("authorization") == f"Bearer {TOKEN}"
            self.authority_reads += 1
            task, page, size = authority[1], int(query["page"][0]), int(query["size"][0])
            if self.fail_refresh:
                return await route.fulfill(status=503, json={"error": "fixture refresh failed"})
            if self.held == (task, page):
                self.started.set()
                await self.release.wait()
                self.released.set()
            total = 2 if self.shrunk else size + 2
            items = [record(task, n) for n in range((page-1)*size+1, min(page*size, total)+1)]
            result = dict(task_id=task, page=page, size=size, items=items, total=total, coverage=COVERAGE,
                          owner_grant="not_recorded", independent_effect="not_recorded")
        elif path.endswith("/authority/casefile"):
            assert request.headers.get("authorization") == f"Bearer {TOKEN}"
            return await route.fulfill(body=self.case_bytes, content_type="application/json",
                                       headers={"X-Casefile-SHA256": hashlib.sha256(self.case_bytes).hexdigest()})
        elif re.fullmatch(r"/api/intercept/history/\d+/execution", path):
            assert request.headers.get("authorization") == f"Bearer {TOKEN}"
            result = {"task_id": "999" if self.wrong_source else "41", "session": "main:0", "seq": 32, "items": []}
        elif path == "/api/exploration/activity/history":
            result = {"items": [{"seq": 32, "worker": "mainagent", "ts": STAMP, "kind": "tool_use",
                                 "tool": "synthetic-inspection", "tool_use_id": "call-1",
                                 "summary": "synthetic recorded event", "detail": "{}"}],
                      "snapshot_cursor": 32, "earliest_cursor": 32, "has_more": False}
        elif path.endswith("/stream"):
            return await route.fulfill(status=204)
        else:
            # The task shell and sidebar read configuration/list APIs. A local blank
            # response leaves their optional widgets empty without contacting ARTEX.
            result = {}
        await route.fulfill(json=result)


async def live_checks(page, fixture, origin):
    await page.goto(f"{origin}/function/tasks/detail/?id=41")
    await page.get_by_role("tab", name="Authority", exact=True).click()
    rows = page.get_by_role("list", name="Recorded interception decisions").get_by_role("button")
    await expect(rows.nth(1)).to_contain_text("fixture-41-tool-2")
    await rows.nth(0).focus()
    await page.keyboard.press("Tab")
    await expect(rows.nth(1)).to_be_focused()
    await page.keyboard.press("Enter")
    await expect(rows.nth(1)).to_have_attribute("aria-pressed", "true")
    await expect(page.get_by_role("figure")).to_contain_text("fixture-41-tool-2")
    assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")

    # Keep the last successful page after a failed refresh, then recover.
    fixture.fail_refresh = True
    await page.get_by_role("button", name="Refresh", exact=True).click()
    await expect(page.get_by_role("alert").filter(has_text="stale")).to_be_visible()
    await expect(rows.nth(1)).to_have_attribute("aria-pressed", "true")
    fixture.fail_refresh = False
    await page.get_by_role("button", name="Refresh", exact=True).click()
    await expect(page.get_by_role("alert").filter(has_text="stale")).to_have_count(0)

    next_page = page.get_by_role("button", name="Next page", exact=True)
    previous_page = page.get_by_role("button", name="Previous page", exact=True)
    await next_page.click()
    await expect(rows).to_have_count(2)
    fixture.shrunk = True
    await page.get_by_role("button", name="Refresh", exact=True).click()
    # Some versions recover automatically. Others keep an empty page with a back button.
    await expect(page.get_by_text(re.compile("No records on this page|No matching recorded decisions|Page 1 of 1")).first).to_be_visible()
    if await previous_page.is_enabled():
        await previous_page.click()
    await expect(rows).to_have_count(2)
    fixture.shrunk = False
    await page.get_by_role("button", name="Refresh", exact=True).click()
    await expect(next_page).to_be_enabled()

    # Same-document task switch while page 2 of the old task is outstanding.
    fixture.held = ("41", 2)
    await next_page.click()
    await asyncio.wait_for(fixture.started.wait(), 5)
    await page.evaluate("history.pushState(null, '', '?id=42')")
    await expect(rows.nth(0)).to_contain_text("fixture-42-tool-1")
    fixture.release.set()
    await asyncio.wait_for(fixture.released.wait(), 5)
    await page.evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")
    await expect(page.get_by_role("figure")).to_contain_text("fixture-42-tool-1")
    await expect(page.get_by_text("fixture-41-tool-1", exact=True)).to_have_count(0)

    await page.evaluate("history.pushState(null, '', '?id=41')")
    await expect(rows.nth(0)).to_contain_text("fixture-41-tool-1")
    fixture.wrong_source = True
    locate = page.get_by_role("button", name="Open original execution", exact=True)
    await locate.click()
    await expect(page.get_by_role("alert").filter(has_text=re.compile("match|scope", re.I))).to_be_visible()
    fixture.wrong_source = False
    await locate.click()
    await expect(page.get_by_role("tab", name="Sessions", exact=True)).to_have_attribute("aria-selected", "true")
    await expect(page.get_by_text("Expanded the tool call for approval #1")).to_be_visible()
    assert sum(path == "/api/intercept/history/1/execution" for _, path in fixture.requests) >= 2


async def download(page, label, destination):
    async with page.expect_download() as pending:
        await page.get_by_role("button", name=label, exact=True).click()
    await (await pending.value).save_as(destination)


async def offline_report(browser, path):
    ctx = await browser.new_context(service_workers="block")
    try:
        other_requests = []
        page = await ctx.new_page()
        async def observe(route):
            other_requests.append(route.request.url)
            await route.abort()
        await ctx.route("**/*", observe)
        await ctx.set_offline(True)
        await page.set_content(path.read_text(encoding="utf-8"))
        await expect(page.get_by_role("heading", name="Snapshot comparison")).to_be_visible()
        body = await page.locator("body").text_content()
        for term in ("fixtureLabel()", "WT-CONFLICT", "UNAUTHENTICATED", "CLAIM_NOT_ASSESSED",
                     "Absent from later snapshot", "execution_status", "demo_future_outcome"):
            assert term in body, term
        assert "EXCLUDED_DEMO_" not in body
        assert not await page.locator("script,iframe,object,embed,img,form,link[href]").count()
        assert not other_requests, other_requests
    finally:
        await ctx.close()


async def portable_checks(page, fixture, args, width):
    demo = args.fixtures
    fixture.case_bytes = (demo / "before.json").read_bytes()
    case = json.loads(fixture.case_bytes)
    task = case["task_id"]
    await page.goto(f"{fixture.origin}/function/tasks/detail/?id={task}&tab=authority")
    button = lambda label: page.get_by_role("button", name=label, exact=True)
    rows = page.get_by_role("list", name="Recorded interception decisions").get_by_role("button")
    await expect(rows.nth(0)).to_contain_text(f"fixture-{task}-tool-1")
    search = page.get_by_role("searchbox", name="Search records")
    await search.fill(f"fixture-{task}-tool-20")
    await expect(page.get_by_text("1 of 20 records on this page", exact=True)).to_be_visible()
    await button("Clear filters").click()
    # Hold one live refresh across Freeze to check that old data cannot overwrite it.
    fixture.held = (task, 1)
    fixture.started.clear()
    fixture.release.clear()
    await button("Refresh").click()
    await asyncio.wait_for(fixture.started.wait(), 5)
    await button("Freeze task").click()
    await expect(page.get_by_role("slider", name="Recorded event")).to_be_visible()
    checkpoint = len(fixture.requests)
    fixture.release.set()
    await expect(rows).to_have_count(case["count"])
    await expect(page.get_by_text(f"fixture-{task}-tool-1", exact=True)).to_have_count(0)
    await expect(rows.filter(has_text="<script>fixtureLabel()</script>")).to_have_count(1)
    await expect(page.locator("script").filter(has_text="fixtureLabel()")).to_have_count(0)

    await page.get_by_text("Filter records", exact=True).click()
    for label, value in (("Tool name", "Index"), ("Decision source", "rule"), ("Decision state", "denied"),
                         ("Decided by", "rule"), ("Recorded agent label", "Binder")):
        await page.get_by_role("textbox", name=label, exact=True).fill(value)
    await page.get_by_role("combobox", name="Evidence gap", exact=True).select_option("WT-CONFLICT")
    await expect(rows).to_have_count(1)
    await expect(page.get_by_role("figure")).to_contain_text("Binder")
    await expect(button("Open original execution")).to_be_disabled()
    await page.get_by_label("Recorded from (UTC)").fill("2099-01-01")
    await expect(rows).to_have_count(0)
    await button("Clear filters").click()
    await expect(rows).to_have_count(case["count"])
    slider = page.get_by_role("slider", name="Recorded event")
    await slider.focus()
    await expect(page.get_by_text("Details show the row at capture time, including fields recorded after the selected event.")).to_be_visible()
    await page.keyboard.press("Home")
    await expect(slider).to_have_value("0")
    await button("Play").click()
    await expect(slider).not_to_have_value("0", timeout=5000)
    await button("Pause").click()
    await slider.focus()
    await page.keyboard.press("End")
    await expect(slider).to_have_attribute("aria-valuetext", re.compile("undated|not recorded", re.I))

    # Visibility change normally wakes polling. Jump over the actual 20-second
    # interval too, catching retained timers as well as visibility listeners.
    await page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
    await page.clock.fast_forward(25000)
    await page.evaluate("new Promise(resolve => requestAnimationFrame(resolve))")
    assert fixture.requests[checkpoint:] == [], fixture.requests[checkpoint:]
    with tempfile.TemporaryDirectory() as artifacts:
        out = Path(artifacts)
        await download(page, "Download casefile", out / "case.json")
        assert (out / "case.json").read_bytes() == fixture.case_bytes
        await download(page, "Download SHA-256", out / "digest")
        assert (out / "digest").read_text().split()[0] == hashlib.sha256(fixture.case_bytes).hexdigest()

        await button("Compare").click()
        await page.get_by_label("Open earlier casefile").set_input_files(demo / "before.json")
        later = page.get_by_label("Open later casefile")
        await later.set_input_files(demo / "restored.json")
        await expect(page.get_by_text(re.compile("dataset_incarnation|incarnation", re.I))
                     .filter(has_text=re.compile("differs|unknown|mismatch", re.I)).last).to_be_visible()
        await later.set_input_files(demo / "after.json")
        await expect(rows.filter(has_text="Added to later snapshot")).to_have_count(1)
        await button("Inspect earlier").click()
        await expect(rows.filter(has_text="Absent from later snapshot")).to_have_count(1)
        await rows.filter(has_text="Shelf count").click()
        await expect(page.get_by_text(re.compile("execution_status")).last).to_be_visible()
        await download(page, "Export reviewer report", out / "report.html")
        await offline_report(page.context.browser, out / "report.html")
        assert fixture.requests[checkpoint:] == [], fixture.requests[checkpoint:]
    # Only this explicit action may POST the source metadata to ARTEX. Test a
    # denied locator and then a fresh lookup that initializes the native Sessions tab.
    chosen = next(r for r in case["records"] if r["tool_name"] == "Catalog")
    await rows.filter(has_text="Catalog").click()
    expected_scope = {key: case[key] for key in ("source_namespace", "dataset_incarnation")}
    expected_scope.update({key: chosen[key] for key in ("run_id", "tool_use_id", "tool_name")})
    fixture.source_request = (f"/api/tasks/{task}/authority/records/{chosen['id']}/source", expected_scope)
    await button("Open original execution").click()
    await expect(page.get_by_role("alert").filter(has_text="exact source unavailable")).to_be_visible()
    fixture.source_ok = True
    await button("Open original execution").click()
    await expect(page.get_by_text(f"Expanded the tool call for approval #{chosen['id']}")).to_be_visible()
    assert fixture.source_request is None
    standalone = f"{fixture.origin}/function/investigation/"
    await page.goto(standalone)
    upload = page.get_by_label("Open casefile", exact=True)
    await upload.set_input_files({"name": "invalid.json", "mimeType": "application/json",
                                 "buffer": b'{"count":0,"count":0}'})
    await expect(page.get_by_role("alert").filter(has_text=re.compile("duplicate", re.I))).to_be_visible()
    await upload.set_input_files(demo / "empty.json")
    await expect(page.get_by_text("An empty view does not establish that no actions occurred.")).to_be_visible()
    unknown = json.loads(fixture.case_bytes)
    unknown["records"][0]["status"] = "synthetic_future_decision"
    await upload.set_input_files({"name": "unknown.json", "mimeType": "application/json",
                                 "buffer": json.dumps(unknown).encode()})
    await expect(page.get_by_role("figure")).to_contain_text("Unrecognized decision state")
    await expect(page.get_by_text("synthetic_future_decision", exact=True)).to_be_visible()
    await upload.set_input_files(demo / "before.json")
    await expect(rows).to_have_count(case["count"])
    await rows.filter(has_text="Catalog").click()
    await expect(button("Open original execution")).to_be_disabled()
    assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    if args.screenshots:
        args.screenshots.mkdir(exist_ok=True, parents=True)
        await page.screenshot(path=args.screenshots / f"frozen-{width}.png", full_page=True)
    if args.large:
        loaded = json.loads(args.large.read_bytes())
        assert loaded["count"] == 2000 and loaded["synthetic"]
        # Wall-clock time, including browser file input and Playwright waits.
        # All measurement uses the Python process monotonic clock.
        start = time.perf_counter_ns()
        await upload.set_input_files(args.large)
        count = page.get_by_text("2000 of 2000 records in this casefile", exact=True)
        await expect(count).to_be_visible(timeout=20000)
        open_ms = (time.perf_counter_ns() - start) / 1e6
        start = time.perf_counter_ns()
        await search.fill("Read card 1995")
        await expect(rows).to_have_count(1)
        await expect(page.get_by_role("figure")).to_contain_text("Read card 1995")
        filter_ms = (time.perf_counter_ns() - start) / 1e6
        debug = await page.context.new_cdp_session(page)
        heap = await debug.send("Runtime.getHeapUsage")
        await debug.detach()
        print(json.dumps({"width": width, "heap_used_bytes_after_filter": heap["usedSize"], "records": 2000, "bytes": args.large.stat().st_size,
                          "sha256": hashlib.sha256(args.large.read_bytes()).hexdigest(),
                          "open_ms": round(open_ms, 1), "filter_select_ms": round(filter_ms, 1)}), flush=True)
    for locale in ("tr", "zh-CN"):
        paths = Path(__file__).resolve().parents[1] / "src/i18n/locales"
        dictionary = json.loads((paths / f"{locale}.json").read_text())
        await page.evaluate("(locale) => localStorage.setItem('artex.locale', locale)", locale)
        await page.reload()
        await page.get_by_label(dictionary["Open casefile"], exact=True).set_input_files(demo / "before.json")
        await expect(page.get_by_role("slider", name=dictionary["Recorded event"])).to_be_visible()
        await expect(page.locator("html")).to_have_attribute("lang", locale)
    print(json.dumps({"width": width, "portable": "pass", "unexpected_requests": len(fixture.violations)}), flush=True)


async def main(args):
    assert (args.static / "function/tasks/detail/index.html").is_file(), "static export missing"
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(StaticFiles, directory=args.static))
    origin = f"http://127.0.0.1:{server.server_port}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(executable_path=args.chromium)
        try:
            for width in (1440, 390):
                fixture = Fixture(origin)
                ctx = await browser.new_context(viewport={"width": width, "height": 900},
                                                locale="en-US", service_workers="block")
                await ctx.route("**/*", fixture.respond)
                await ctx.add_init_script(f"localStorage.setItem('artex_token',{json.dumps(TOKEN)})")
                page = await ctx.new_page()
                page.set_default_timeout(7000)
                await page.clock.install()
                errors = []
                page.on("pageerror", lambda e: errors.append(str(e)))
                try:
                    await live_checks(page, fixture, origin)
                    assert not fixture.violations, fixture.violations
                    assert not errors, errors
                    print(json.dumps({"width": width, "chromium": browser.version, "live": "pass",
                                      "authority_reads": fixture.authority_reads}), flush=True)
                    if not args.live_only:
                        await portable_checks(page, fixture, args, width)
                        assert not fixture.violations, fixture.violations
                        assert not errors, errors
                except Exception:
                    print("Browser errors", errors)
                    print("API requests", fixture.requests[-30:])
                    print("Page text", (await page.locator("body").inner_text())[-3500:])
                    raise
                finally:
                    await ctx.close()
        finally:
            await browser.close()
            server.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).resolve().parents[2] / "docs/wolftrax-demo")
    parser.add_argument("--screenshots", type=Path, help="optional folder for rendered Frozen view captures")
    parser.add_argument("--large", type=Path, help="large.json from the synthetic demo producer")
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    parser.add_argument("--live-only", action="store_true")
    asyncio.run(main(parser.parse_args()))
