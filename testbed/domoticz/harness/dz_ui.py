"""The Domoticz web UI in a headless browser (Playwright/Chromium on the host, through tunnel.py): log in as one
account through the UI's own login form, open a device's Log page and read the rendered Text log table cells
(Date, Data, User) from the DOM, with every page of the table shown."""
from dz_api import ACCOUNTS

READ_TABLE = """() => {
  const t = document.querySelector('table.entity-log-table');
  if (!t) return null;
  try { $(t).DataTable().page.len(-1).draw(); } catch (e) {}
  const head = [...t.querySelectorAll('thead th')].map(x => x.innerText.trim());
  const rows = [...t.querySelectorAll('tbody tr')].map(tr => [...tr.querySelectorAll('td')].map(td => td.innerText.trim()));
  return {head: head, rows: rows};
}"""


class UiSession:
    def __init__(self, browser, base, account):
        self.base = base
        self.account = account
        self.ctx = browser.new_context(viewport={"width": 1280, "height": 1400})
        self.page = self.ctx.new_page()
        self.page.goto(base + "/", wait_until="networkidle")
        self.page.fill("#username", account)
        self.page.fill("#password", ACCOUNTS[account]["password"])
        self.page.click("button[type=submit], #login, button:has-text('Login')")
        self.page.wait_for_url("**/#/Dashboard", timeout=20000)
        self._dismiss()

    def _dismiss(self):
        for sel in ("button:has-text('Close')",):
            try:
                if self.page.locator(sel).first.is_visible(timeout=1500):
                    self.page.locator(sel).first.click()
            except Exception:                                         # noqa: BLE001
                pass

    def text_log(self, idx, screenshot=None):
        """Rendered rows of the device's Text log table, newest first, as [[Date, Data, User], ...]."""
        self.page.goto(self.base + "/#/Dashboard", wait_until="networkidle")
        self.page.goto(self.base + "/#/Devices/%s/Log" % idx, wait_until="networkidle")
        self.page.wait_for_selector("table.entity-log-table tbody tr", timeout=20000)
        self.page.wait_for_timeout(800)
        self._dismiss()
        t = self.page.evaluate(READ_TABLE)
        if screenshot:
            self.page.screenshot(path=screenshot, full_page=True)
        if not t:
            return None
        assert t["head"][:3] == ["Date", "Data", "User"], t["head"]
        return [r[:3] for r in t["rows"] if len(r) >= 3]
