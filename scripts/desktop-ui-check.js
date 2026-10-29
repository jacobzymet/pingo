// Playwright CLI run-code snippet. The bridge is mocked; no files/network are changed.
async (page) => {
  await page.addInitScript(() => {
    let profiles = [],
      selected = null,
      seq = 0;
    let job = { state: "idle", running: false, action: null };
    const events = [];
    const defaultChecks = [
      { name: "Connection and shared key", status: "pass", detail: "Settings are valid." },
      { name: "Endpoint addresses", status: "warn", detail: "Replace example-only IPv4s." },
      { name: "Peer and firewall", status: "manual", detail: "Check both computers." },
    ];
    let checks = defaultChecks;
    window.fixtureChecks = (value) => { checks = value || defaultChecks; };
    window.fixtureStarts = [];
    const interfaces = [
      { name: "Ethernet", address: "192.168.1.10", up: true },
      { name: "Wi-Fi", address: "10.0.0.10", up: false },
      { name: "Work VPN", address: "10.77.0.1", up: true },
      { name: "Loopback", address: "127.0.0.1", up: true, loopback: true },
    ];
    const emit = (event) =>
      events.push({ ...event, seq: ++seq, at: Date.now() / 1000 });
    const ok = (data) => ({ ok: true, data });
    window.fixtureEmit = emit;
    window.fixtureJob = (value) => {
      job = value;
    };
    window.pywebview = {
      api: {
        snapshot: async (after) =>
          ok({
            version: "0.3.0",
            platform: "win32",
            elevated: true,
            profiles,
            selected,
            job,
            events: events.filter((e) => e.seq > after),
            missed: 0,
            metrics: {},
            local_addresses: ["192.0.2.10"],
            interfaces,
            recovery_table: "",
          }),
        create_key: async () => ok("C:\\Pingo-test\\peer.key"),
        refresh_addresses: async () => ok({ interfaces, error: "" }),
        choose: async (kind) =>
          ok(kind === "file" ? "C:\\Pingo-test\\sample.zip" : null),
        save_connection: async (data) => {
          if (!/^\d+\.\d+\.\d+\.\d+$/.test(data.peer))
            return {
              ok: false,
              error: "Enter a valid IPv4 address.",
              hint: "Use the other computer’s address.",
            };
          const p = {
            address: "10.77.0.1/30",
            interface: "pingo0",
            receive_dir: "C:\\Pingo-test\\received",
            routes: [],
            allowed_source: [],
            dns: [],
            no_dns: false,
            default_route: false,
            vpn_listen: false,
            kill_switch: null,
            wintun_dll: "",
            ...data,
            id: data.id || "a".repeat(32),
          };
          profiles = [p];
          selected = p.id;
          return ok(p);
        },
        start: async (_id, action, payload) => {
          window.fixtureStarts.push(action);
          if (action === "listen")
            job = { state: "listening", action, running: true };
          else {
            job = { state: "completed", action, running: false };
            if (action === "message")
              emit({ event: "sent_message", text: payload.text });
            if (action === "probe")
              emit({ event: "peer_verified", peer: profiles[0].peer });
            if (action === "file") {
              job.progress = {
                phase: "verified",
                name: "sample.zip",
                done: 8192,
                total: 8192,
              };
              emit({ event: "sent_file", name: "sample.zip" });
            }
          }
          emit({ event: "state", state: job.state });
          emit({
            event: "traffic",
            direction: "tx",
            layer: "icmp",
            bytes: 32,
            packets_total: 1,
            bytes_total: 32,
            bytes_per_second: 32,
            wire_hex: "0123abcd".repeat(8),
          });
          return ok({ started: action });
        },
        stop: async () => {
          job = { state: "stopped", running: false };
          return ok({ stopping: false });
        },
        check_setup: async () => ok(checks),
      },
    };
  });
  await page.goto("http://127.0.0.1:8766/");
  await page.getByRole("status").filter({ hasText: "Setup needed" }).waitFor();
  if ((await page.locator(".address-row").count()) !== 4)
    throw Error("Missing adapter addresses");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await page.getByRole("button", { name: "Use 10.77.0.1 on Work VPN" }).click();
  if ((await page.locator("#profile-bind").inputValue()) !== "10.77.0.1")
    throw Error("Adapter address did not fill setup");
  await page.keyboard.press("Escape");
  if (await page.locator("#view-direct").isVisible())
    throw Error("Unconfigured actions were visible");
  await page.keyboard.press("Control+3");
  if (!(await page.locator("#view-check").isVisible()))
    throw Error("Settings were unavailable before adding a connection");
  await page.keyboard.press("Control+1");
  await page.setViewportSize({ width: 1180, height: 850 });
  await page.screenshot({
    path: "output/playwright/desktop-welcome.png",
    fullPage: true,
  });
  await page
    .getByRole("button", { name: "Add a connection", exact: true })
    .click();
  await page.getByLabel("Connection name").fill("Home computer");
  await page.getByLabel("Other computer’s IPv4").fill("not-an-ip");
  await page.getByRole("button", { name: "Generate a new shared key" }).click();
  await page
    .getByRole("button", { name: "Save connection", exact: true })
    .click();
  await page
    .locator("#dialog-error")
    .filter({ hasText: "valid IPv4" })
    .waitFor();
  await page.getByLabel("Other computer’s IPv4").fill("192.0.2.20");
  await page.getByLabel("This computer’s IPv4").fill("192.0.2.10");
  await page
    .getByRole("button", { name: "Save connection", exact: true })
    .click();
  await page.locator("#connection-dialog").waitFor({ state: "hidden" });
  if (await page.locator("#local-network").evaluate((element) => element.open))
    throw Error("Address inventory should collapse after setup");
  await page.locator("#health-title").filter({ hasText: "1 setup warning" }).waitFor();
  if (await page.locator("#trace").isVisible())
    throw Error("Packet trace should start collapsed");
  if (
    !(await page
      .getByRole("button", { name: "Send message", exact: true })
      .isDisabled())
  )
    throw Error("Empty message could be sent");
  await page
    .getByRole("textbox", { name: "Message", exact: true })
    .fill("é".repeat(30001));
  if (
    !(await page
      .getByRole("button", { name: "Send message", exact: true })
      .isDisabled())
  )
    throw Error("Oversized UTF-8 message could be sent");
  if (
    (await page.locator("#message-size").textContent()) !==
    "60,002 / 60,000 bytes"
  )
    throw Error("UTF-8 size count is incorrect");
  await page
    .getByRole("textbox", { name: "Message", exact: true })
    .fill("<script>window.injected=true</script>");
  await page
    .getByRole("textbox", { name: "Message", exact: true })
    .press("Control+Enter");
  await page
    .locator("#activity")
    .filter({ hasText: "Message received by peer" })
    .waitFor();
  if (await page.evaluate(() => Boolean(window.injected)))
    throw Error("Message HTML executed");
  await page.getByRole("tab", { name: "Message", exact: true }).focus();
  await page.keyboard.press("ArrowRight");
  await page.locator('#tab-file[aria-selected="true"]').waitFor();
  if (await page.locator("#task-message").isVisible())
    throw Error("Message panel did not hide");
  await page.getByRole("button", { name: /^Choose a file/ }).click();
  await page.getByRole("button", { name: "Send file", exact: true }).click();
  await page
    .locator("#operation-detail")
    .filter({ hasText: "Verified by receiver" })
    .waitFor();
  await page.getByRole("tab", { name: "Receive", exact: true }).click();
  await page
    .getByRole("button", { name: "Start receiving", exact: true })
    .click();
  await page.getByRole("status").filter({ hasText: "Receiving" }).waitFor();
  await page.getByRole("tab", { name: "Message", exact: true }).click();
  if (
    !(await page
      .getByRole("button", { name: "Send message", exact: true })
      .isDisabled())
  )
    throw Error("Concurrent send was enabled");
  await page.getByRole("button", { name: "Stop", exact: true }).click();
  await page.getByRole("status").filter({ hasText: "Stopped" }).waitFor();
  await page.evaluate(() =>
    window.fixtureJob({
      state: "stopped",
      running: false,
      action: "file",
      progress: {
        phase: "sending",
        name: "sample.zip",
        done: 4096,
        total: 8192,
      },
    }),
  );
  await page
    .locator("#operation-label")
    .filter({ hasText: "Stopped: sample.zip" })
    .waitFor();
  if (
    !(await page.locator("#operation-detail").textContent()).includes("resume")
  )
    throw Error("Stopped transfer lacks resume guidance");
  await page.evaluate(() =>
    window.fixtureJob({ state: "stopped", running: false }),
  );
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.locator("#setup-results summary").click();
  await page
    .getByRole("button", { name: "Run setup check", exact: true })
    .click();
  await page.locator(".check-row").first().waitFor();
  await page.getByRole("button", { name: "Test peer connection", exact: true }).click();
  await page.locator("#peer-test-result").filter({ hasText: "Authenticated ICMP worked" }).waitFor();
  if (!(await page.locator("#peer-test-result").textContent()).includes("does not verify"))
    throw Error("Peer verification overstates what was tested");
  const startsBeforeFailure = await page.evaluate(() => window.fixtureStarts.length);
  await page.evaluate(() => window.fixtureChecks([
    { name: "ICMP socket and local address", status: "fail", detail: "Run as Administrator/root." },
  ]));
  await page.getByRole("button", { name: "Send & receive", exact: true }).click();
  await page.getByRole("button", { name: "Send message", exact: true }).click();
  await page.locator("#view-check").waitFor({ state: "visible" });
  await page.locator("#toast-title").filter({ hasText: "Fix the failed setup checks" }).waitFor();
  if ((await page.evaluate(() => window.fixtureStarts.length)) !== startsBeforeFailure)
    throw Error("Failed preflight still started networking");
  await page.evaluate(() => window.fixtureChecks([
    { name: "VPN endpoint overlap (VPN only)", status: "fail", detail: "Change tunnel subnet." },
  ]));
  await page.getByRole("button", { name: "Send & receive", exact: true }).click();
  await page.getByRole("button", { name: "Send message", exact: true }).click();
  await page.getByRole("status").filter({ hasText: "Completed" }).waitFor();
  if ((await page.evaluate(() => window.fixtureStarts.length)) !== startsBeforeFailure + 1)
    throw Error("VPN-only failure incorrectly blocked a direct message");
  await page.evaluate(() => window.fixtureChecks(null));
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Run setup check", exact: true }).click();
  await page.locator(".network-guide summary").click();
  for (const [width, height] of [[1180, 850], [390, 844]]) {
    await page.setViewportSize({ width, height });
    if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth))
      throw Error(`Setup guidance overflows at ${width}`);
    await page.screenshot({ path: `output/playwright/network-checks-${width}.png`, fullPage: true });
  }
  await page.setViewportSize({ width: 1180, height: 850 });
  await page.getByRole("button", { name: "VPN tunnel", exact: true }).click();
  await page.locator("#vpn-role").selectOption("responder");
  if ((await page.locator("#vpn-address").inputValue()) !== "10.77.0.2/30")
    throw Error("Wrong responder address");
  if (!(await page.locator("#vpn-kill").isDisabled()))
    throw Error("Responder kill switch enabled");
  await page.locator("#vpn-role").selectOption("client");
  await page.getByLabel("Route through the tunnel").selectOption("default");
  if ((await page.locator("#vpn-sources").inputValue()) !== "0.0.0.0/0")
    throw Error("Default routing source missing");
  await page
    .getByRole("button", { name: "Send & receive", exact: true })
    .click();
  await page.locator(".trace-summary").click();
  await page
    .getByRole("button", { name: "Pause display", exact: true })
    .click();
  const count = await page.locator("#trace .packet").count();
  await page.evaluate(() =>
    window.fixtureEmit({
      event: "traffic",
      direction: "rx",
      layer: "icmp",
      bytes: 4,
      packets_total: 1,
      bytes_total: 4,
      bytes_per_second: 4,
      wire_hex: "deadbeef",
    }),
  );
  await page.waitForTimeout(600);
  if ((await page.locator("#trace .packet").count()) !== count)
    throw Error("Pause did not freeze the display");
  await page.getByLabel("Show hex").uncheck();
  if ((await page.locator("#trace pre").count()) !== 0)
    throw Error("Paused hex toggle failed");
  await page.getByLabel("Filter packets").selectOption("rx");
  if ((await page.locator("#trace .packet").count()) !== 0)
    throw Error("Paused filter did not use frozen packets");
  await page.getByLabel("Show hex").check();
  await page
    .getByRole("button", { name: "Resume display", exact: true })
    .click();
  await page.getByLabel("Filter packets").selectOption("rx");
  if ((await page.locator("#trace .packet").count()) !== 1)
    throw Error("Trace filtering failed");
  await page.getByLabel("Show hex").uncheck();
  if ((await page.locator("#trace pre").count()) !== 0)
    throw Error("Hex toggle failed");
  await page.getByLabel("Show hex").check();
  await page.getByLabel("Filter packets").selectOption("all");
  await page.locator(".trace-summary").click();
  if (await page.locator("#trace").isVisible())
    throw Error("Trace did not collapse");
  await page.locator(".trace-summary").click();
  await page.getByRole("tab", { name: "File", exact: true }).click();
  await page.keyboard.press("Home");
  if (
    (await page
      .getByRole("tab", { name: "Message", exact: true })
      .getAttribute("aria-selected")) !== "true"
  )
    throw Error("Home key did not select first tab");
  if (
    (await page.locator("#message").inputValue()) !==
    "<script>window.injected=true</script>"
  )
    throw Error("Switching tabs lost the draft");
  await page.setViewportSize({ width: 1180, height: 850 });
  await page.evaluate(() => window.scrollTo(0, 0));
  if (
    await page.evaluate(
      () => document.documentElement.scrollHeight > window.innerHeight,
    )
  )
    throw Error("Desktop workspace scrolls the document");
  await page.screenshot({
    path: "output/playwright/desktop-configured.png",
    fullPage: true,
  });
  for (const [width, height] of [
    [760, 620],
    [390, 844],
  ]) {
    await page.setViewportSize({ width, height });
    await page.evaluate(() => window.scrollTo(0, 0));
    if (
      await page.evaluate(
        () => document.documentElement.scrollWidth > window.innerWidth,
      )
    )
      throw Error(`Horizontal overflow at ${width}`);
    await page.screenshot({
      path: `output/playwright/desktop-${width}.png`,
      fullPage: true,
    });
  }
  await page.setViewportSize({ width: 1180, height: 850 });
  await page.getByRole("button", { name: "Edit", exact: true }).focus();
  await page.keyboard.press("Enter");
  await page.getByRole("dialog").waitFor();
  await page.screenshot({ path: "output/playwright/desktop-setup.png" });
  await page.keyboard.press("Escape");
  await page.keyboard.press("Control+n");
  await page.getByRole("dialog").waitFor();
  if (
    (await page.locator("#connection-dialog-title").textContent()).trim() !==
    "Add a connection"
  )
    throw Error("New connection shortcut opened the wrong dialog");
  await page.keyboard.press("Escape");
  return "Passed: guided setup, UTF-8 limits, keyboard send and tabs, draft preservation, safe message rendering, file progress, receive/stop, concurrency, automatic diagnostics, peer verification, failed-preflight blocking, VPN-only check scope, VPN defaults, frozen trace filtering, hex, collapse, keyboard dialog, 3 viewport sizes.";
}
