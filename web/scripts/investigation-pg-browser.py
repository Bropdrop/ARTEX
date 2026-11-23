"""Browser driver for the opt-in Go TestInvestigationBrowser integration test."""
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright


def check(origin, task, phase, out):
    count = 1 if phase == "before" else 2
    authority = f"/api/tasks/{task}/authority"
    violations, requests, errors = [], [], []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=shutil.which("chromium"))
        ctx = browser.new_context(locale="en-US", service_workers="block")
        token = os.environ["WOLFTRAX_FIXTURE_TOKEN"]
        ctx.add_init_script(f"localStorage.setItem('artex_token', {json.dumps(token)})")

        def observe(route):
            req = route.request
            url = urlsplit(req.url)
            static_head = req.method == "HEAD" and not url.path.startswith("/api/")
            if ((req.method != "GET" and not static_head) or f"{url.scheme}://{url.netloc}" != origin
                    or url.path.startswith("/api/traffic/replay")):
                violations.append((req.method, url.path))
                route.abort()
            else:
                if url.path.startswith("/api/"):
                    requests.append(url.path)
                route.continue_()

        ctx.route("**/*", observe)
        page = ctx.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(f"{origin}/function/tasks/detail/?id={task}&tab=authority")
        rows = page.get_by_role("list", name="Recorded interception decisions").get_by_role("button")
        button = lambda name: page.get_by_role("button", name=name, exact=True)
        expect(rows).to_have_count(count)
        assert authority in requests
        with page.expect_response(lambda res: urlsplit(res.url).path == authority + "/casefile") as captured:
            button("Freeze task").click()
        response = captured.value
        assert response.ok and response.headers["cache-control"] == "no-store"
        expected_digest = response.headers["x-casefile-sha256"]
        expect(page.get_by_role("heading", name="Frozen casefile")).to_be_visible()
        expect(rows).to_have_count(count)
        rows.filter(has_text="Catalog fixture").click()
        expect(page.get_by_role("figure")).to_contain_text("Catalog fixture")
        expect(page.get_by_role("slider", name="Recorded event")).to_be_visible()
        checkpoint = len(requests)

        def download(label, path):
            with page.expect_download() as capture:
                button(label).click()
            capture.value.save_as(path)

        path = out / (phase + ".json")
        download("Download casefile", path)
        body = path.read_bytes()
        digest = hashlib.sha256(body).hexdigest()
        assert digest == expected_digest and b"EXCLUDED_FIXTURE_" not in body
        case = json.loads(body)
        assert case["task_id"] == task and case["count"] == count and case["synthetic"]
        summary = dict(phase=phase, records=count, bytes=len(body), sha256=digest)
        if phase == "after":
            button("Compare").click()
            page.get_by_label("Open earlier casefile").set_input_files(out / "before.json")
            page.get_by_label("Open later casefile").set_input_files(path)
            expect(page.get_by_role("heading", name="Snapshot comparison")).to_be_visible()
            expect(page.get_by_text("Added 1 · Absent from later snapshot 0 · Changed 1", exact=True)).to_be_visible()
            report = out / "review.html"
            download("Export reviewer report", report)
            # Render the exact downloaded HTML in a new, network-denied context.
            # Managed Chromium can prohibit file: navigation independently of HTML.
            offline = browser.new_context(service_workers="block", offline=True)
            viewer = offline.new_page()
            viewer.on("request", lambda req: violations.append(("report", req.url)))
            viewer.set_content(report.read_text(encoding="utf-8"))
            expect(viewer.get_by_role("heading", name="Snapshot comparison")).to_be_visible()
            text = viewer.locator("body").text_content()
            for value in ("Catalog fixture", "Index fixture", "WT-CONFLICT", "status", "allowed", "denied",
                          "UNAUTHENTICATED", "CLAIM_NOT_ASSESSED", "<script>fixtureLabel()</script>"):
                assert value in text, value
            assert "EXCLUDED_FIXTURE_" not in text and viewer.locator("script,img,iframe").count() == 0
            summary.update(report_sha256=hashlib.sha256(report.read_bytes()).hexdigest(), added=1, changed=1)
            offline.close()
        assert requests[checkpoint:] == [], requests[checkpoint:]
        assert not violations and not errors, (violations, errors)
        print(json.dumps({**summary, "offline_api_requests": 0, "unexpected_requests": 0, "chromium": browser.version}))
        browser.close()


if __name__ == "__main__":
    check(sys.argv[1], sys.argv[2], sys.argv[3], Path(sys.argv[4]))
