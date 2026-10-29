"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const state = {
    ready: false,
    profiles: [],
    selected: null,
    job: {},
    seq: 0,
    packets: [],
    activity: [],
    file: null,
    editing: null,
    paused: false,
    frozenPackets: [],
    pending: new Set(),
    view: "direct",
    task: "message",
    platform: "",
    missed: 0,
    errorSeq: 0,
    localAddresses: [],
    checks: null,
    launching: false,
    checkRequest: 0,
  };
  const labels = {
    idle: "Ready",
    starting: "Starting",
    connecting: "Connecting",
    connected: "Connected",
    listening: "Receiving",
    reconnecting: "Reconnecting",
    stopping: "Stopping safely",
    completed: "Completed",
    stopped: "Stopped",
    failed: "Needs attention",
  };
  const profile = () => state.profiles.find((p) => p.id === state.selected);
  const bytes = (value) => {
    const n = Number(value) || 0;
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / 1048576).toFixed(1)} MiB`;
  };
  const list = (value) =>
    value
      .split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean);
  const time = (value) =>
    new Date(value * 1000).toLocaleTimeString([], { hour12: false });
  function toast(title, hint = "", success = false) {
    $("toast-title").textContent = title;
    $("toast-hint").textContent = hint;
    $("toast").dataset.kind = success ? "success" : "error";
    $("toast").hidden = false;
  }
  async function api(method, ...args) {
    if (!window.pywebview?.api)
      throw {
        message: "Open Pingo in its desktop window.",
        hint: "Run pingo gui or open Pingo.exe. Browser previews cannot access your files or network.",
      };
    let response;
    try {
      response = await window.pywebview.api[method](...args);
    } catch (error) {
      throw {
        message: error.message || "The desktop could not complete this action.",
        hint: "Try again and check the activity log.",
      };
    }
    if (!response.ok) throw { message: response.error, hint: response.hint };
    return response.data;
  }
  async function action(button, callback) {
    if (button) {
      if (state.pending.has(button)) return;
      state.pending.add(button);
      button.disabled = true;
    }
    try {
      return await callback();
    } catch (error) {
      if ($("connection-dialog").open) {
        $("dialog-error").textContent = [error.message, error.hint]
          .filter(Boolean)
          .join(" ");
        $("dialog-error").hidden = false;
      } else toast(error.message || "Action failed.", error.hint || "");
    } finally {
      if (button) {
        state.pending.delete(button);
        button.disabled = false;
      }
      renderControls();
    }
  }
  function renderControls() {
    const p = profile(),
      running = Boolean(state.job.running),
      busy = running || state.launching;
    document.querySelectorAll(".network-action").forEach((b) => {
      b.disabled = !p || busy;
    });
    $("send-file").disabled = !p || busy || !state.file;
    const messageBytes = new TextEncoder().encode($("message").value).length;
    const oversized = messageBytes > 60000;
    $("send-message").disabled = !p || busy || !messageBytes || oversized;
    $("message").setCustomValidity(
      oversized ? "Keep your message under 60,000 UTF-8 bytes." : "",
    );
    $("message-size").textContent =
      `${messageBytes.toLocaleString()} / 60,000 bytes`;
    $("message-size").dataset.invalid = oversized;
    [
      "edit-connection",
      "pair-connection",
      "open-received",
      "run-check",
    ].forEach((id) => {
      $(id).disabled = !p || (busy && id !== "open-received");
    });
    [
      "new-connection",
      "welcome-create",
      "import-connection",
      "connection-select",
      "elevate",
    ].forEach((id) => {
      $(id).disabled = busy;
    });
    $("unlock").disabled = busy || !state.ready;
    $("stop").disabled = !running || state.job.state === "stopping";
    document.body.dataset.configured = Boolean(p);
    $("welcome").hidden = Boolean(p) || state.view === "check";
    $("peer-link").hidden = !p;
    $("local-ip").textContent = p
      ? p.bind === "0.0.0.0"
        ? "All interfaces"
        : p.bind
      : "Not configured";
    $("peer-ip").textContent = p?.peer || "Add a connection";
    $("receive-folder").textContent =
      p?.receive_dir || "Pingo’s private receive folder";
    $("receive-folder").title = p?.receive_dir || "";
    $("connection-health").hidden = !p || state.view === "check";
    $("receive-copy").textContent =
      running && state.job.action === "listen"
        ? "Listening for messages and files. Keep this window open."
        : "Keep this window open while the other computer sends.";
    $("receive-title").textContent =
      running && state.job.action === "listen"
        ? "Receiving from your peer."
        : "Receive from your peer.";
    $("receive").textContent =
      running && state.job.action === "listen"
        ? "Receiving…"
        : "Start receiving";
    document.querySelectorAll("[data-task]").forEach((tab) => {
      tab.dataset.busy =
        running &&
        (tab.dataset.task === state.job.action ||
          (tab.dataset.task === "receive" && state.job.action === "listen"));
    });
    $("task-hint").textContent = running
      ? "Stop the current activity to switch tasks."
      : state.task === "receive"
        ? "Start here, then send from your peer."
        : "Start Receive on your peer first.";
    $("trace-state").textContent = state.paused
      ? "Paused"
      : running && state.job.action !== "unlock"
        ? "Live"
        : state.packets.length
          ? `${state.packets.length} packets`
          : "Waiting";
    $("trace-state").dataset.active =
      !state.paused && running && state.job.action !== "unlock";
    $("export-trace").disabled = !state.seq;
    $("file-limit").textContent = p
      ? `${bytes(p.max_file_bytes)} maximum`
      : "64 MiB per file by default";
    $("status").textContent = state.ready
      ? p
        ? labels[state.job.state] || "Ready"
        : "Setup needed"
      : "Desktop window required";
    $("status").dataset.state = state.job.state || "idle";
    $("operation").hidden = !running && !state.job.progress;
    $("operation").dataset.state = state.job.state || "idle";
    const prog = state.job.progress;
    $("progress").hidden = !prog;
    $("operation").dataset.progress = Boolean(prog);
    if (running || prog) {
      const verb =
        state.job.action === "file"
          ? "File transfer"
          : state.job.action === "message"
            ? "Message"
            : state.job.action === "vpn"
              ? "VPN"
              : state.job.action === "unlock"
                ? "Recovery"
                : state.job.action === "probe"
                  ? "Peer test"
                  : "Receive";
      const interrupted =
        prog &&
        prog.phase !== "verified" &&
        (!running || state.job.state === "stopping");
      const phase = interrupted
        ? labels[state.job.state] || "Stopped"
        : prog?.phase;
      $("operation-label").textContent = prog
        ? `${phase.charAt(0).toUpperCase() + phase.slice(1)}: ${prog.name || "file"}`
        : `${verb} · ${labels[state.job.state] || "Starting"}`;
      $("operation-detail").textContent =
        state.job.state === "stopping"
          ? "Waiting for connections and network settings to clean up…"
          : prog
            ? `${bytes(prog.done)} of ${bytes(prog.total)}${prog.phase === "verified" ? " · Verified by receiver" : interrupted && state.job.action === "file" ? " · Send the same file again to resume." : ""}`
            : state.job.action === "listen"
              ? "Waiting for messages and files from your peer."
              : state.job.action === "vpn"
                ? "Stop the tunnel to restore your network settings."
                : "Waiting for your peer…";
      if (prog) {
        $("progress").max = Math.max(prog.total, 1);
        $("progress").value = prog.total
          ? prog.done
          : prog.phase === "verified"
            ? 1
            : 0;
      } else $("progress").removeAttribute("value");
      $("stop").hidden = !running;
    }
    state.pending.forEach((button) => {
      button.disabled = true;
    });
  }
  function updateProfiles(profiles, selected) {
    const before = state.selected,
      changed = JSON.stringify(profiles) !== JSON.stringify(state.profiles);
    state.profiles = profiles;
    state.selected = selected;
    if (changed || before !== selected) {
      $("connection-select").replaceChildren();
      if (!profiles.length)
        $("connection-select").add(new Option("No connection yet", ""));
      for (const p of profiles)
        $("connection-select").add(new Option(p.name, p.id));
      $("connection-select").value = selected || "";
      loadVpn();
      state.checks = null;
      state.checkRequest++;
      $("peer-test-result").textContent =
        "Not tested. This checks direct mode, not a VPN responder or Internet exit.";
      void refreshChecks();
    }
  }
  function renderChecks() {
    const fragment = document.createDocumentFragment();
    for (const c of state.checks || []) {
      const row = document.createElement("div"),
        badge = document.createElement("span"),
        info = document.createElement("div"),
        title = document.createElement("strong"),
        detail = document.createElement("p");
      row.className = "check-row";
      badge.className = "check-badge";
      badge.dataset.status = c.status;
      badge.textContent = { manual: "Check", warn: "Warning", fail: "Failed", pass: "Passed" }[c.status] || c.status;
      title.textContent = c.name;
      detail.textContent = c.detail;
      info.append(title, detail);
      row.append(badge, info);
      fragment.append(row);
    }
    $("checks").replaceChildren(fragment);
    const failed = state.checks.filter((c) => c.status === "fail").length,
      warnings = state.checks.filter((c) => c.status === "warn").length;
    $("connection-health").dataset.status = failed ? "fail" : warnings ? "warn" : "manual";
    $("health-title").textContent = failed
      ? `${failed} setup check${failed === 1 ? " needs" : "s need"} attention`
      : warnings
        ? `${warnings} setup warning${warnings === 1 ? "" : "s"}`
        : "Local checks complete · peer unverified";
    $("health-detail").textContent =
      "VPN-only results affect VPN. Review checks and test peer connection in Settings.";
  }
  async function refreshChecks() {
    if (!profile()) return null;
    const request = ++state.checkRequest;
    state.checks = null;
    $("connection-health").dataset.status = "manual";
    $("health-title").textContent = state.job.running
      ? "Stop the current activity to run local checks"
      : "Checking this computer…";
    $("health-detail").textContent = "Peer reachability has not been tested.";
    $("checks").textContent = $("health-title").textContent;
    if (state.job.running) return null;
    try {
      const checks = await api("check_setup", state.selected);
      if (request !== state.checkRequest) return null;
      state.checks = checks;
      renderChecks();
      return checks;
    } catch (error) {
      if (request === state.checkRequest) {
        $("health-title").textContent = "Local checks could not finish";
        $("health-detail").textContent = error.message;
        $("checks").textContent = error.message;
      }
      return null;
    }
  }
  function activityText(e) {
    if (e.event === "peer_verified")
      return `Peer verified: authenticated ICMP handshake with ${e.peer}`;
    if (e.event === "message") return `Received message: ${e.text}`;
    if (e.event === "sent_message")
      return `Message received by peer: ${e.text}`;
    if (e.event === "sent_file") return `File verified by peer: ${e.name}`;
    if (e.event === "received_file")
      return `Received and verified: ${e.name} (${bytes(e.size)})`;
    if (e.event === "log" || e.event === "error") return e.text;
    if (e.event === "state")
      return `${labels[e.state] || e.state}${e.delay ? ` · retry ${e.attempt} in ${e.delay}s` : ""}`;
    return null;
  }
  function addEvents(events) {
    for (const e of events) {
      state.seq = Math.max(state.seq, e.seq);
      if (e.event === "peer_verified" && e.peer === profile()?.peer)
        $("peer-test-result").textContent =
          `Verified ${e.peer} at ${time(e.at)}. Authenticated ICMP worked in both directions. ` +
          "This does not verify larger transfers, VPN routing or an Internet exit.";
      if (e.event === "traffic") {
        state.packets.push(e);
        if (state.packets.length > 120) state.packets.shift();
      }
      const text = activityText(e);
      if (text) {
        state.activity.push({ ...e, text });
        if (state.activity.length > 100) state.activity.shift();
      }
      if ((e.event === "log" && e.level === "error") || e.event === "error")
        state.errorSeq = e.seq;
    }
    if (events.some((e) => activityText(e))) renderActivity();
    if (!state.paused && events.some((e) => e.event === "traffic"))
      renderTrace();
  }
  function renderActivity() {
    const el = $("activity"),
      nearEnd = el.scrollTop + el.clientHeight >= el.scrollHeight - 40;
    const fragment = document.createDocumentFragment();
    for (const e of state.activity) {
      const row = document.createElement("li"),
        stamp = document.createElement("time"),
        text = document.createElement("span");
      stamp.textContent = time(e.at);
      text.textContent = e.text;
      text.className = "activity-text";
      row.dataset.level = e.level || "info";
      row.append(stamp, text);
      fragment.append(row);
    }
    el.replaceChildren(fragment);
    $("activity-count").textContent =
      `${state.activity.length} ${state.activity.length === 1 ? "event" : "events"}`;
    if (nearEnd) el.scrollTop = el.scrollHeight;
  }
  function renderTrace() {
    const el = $("trace"),
      nearEnd = el.scrollTop + el.clientHeight >= el.scrollHeight - 50;
    const filter = $("trace-filter").value,
      hex = $("show-hex").checked,
      fragment = document.createDocumentFragment();
    const packets = (state.paused ? state.frozenPackets : state.packets).filter(
      (p) => filter === "all" || p.direction === filter,
    );
    if (!packets.length)
      fragment.append(
        Object.assign(document.createElement("p"), {
          className: "trace-empty",
          textContent: "No packets for this filter yet.",
        }),
      );
    for (const p of packets) {
      const row = document.createElement("div"),
        header = document.createElement("div");
      row.className = "packet";
      header.className = "packet-header";
      for (const [text, cls] of [
        [time(p.at), ""],
        [p.direction.toUpperCase(), "packet-direction"],
        [p.layer.toUpperCase(), ""],
        [`${p.bytes} B · #${p.packets_total}`, "packet-size"],
      ]) {
        const span = document.createElement("span");
        span.textContent = text;
        span.className = cls;
        span.dataset.direction = p.direction;
        header.append(span);
      }
      row.append(header);
      if (hex && p.wire_hex) {
        const pre = document.createElement("pre");
        pre.textContent = p.wire_hex.match(/.{1,2}/g).join(" ");
        row.append(pre);
      }
      if (p.layer === "tun") {
        const pre = document.createElement("pre");
        pre.textContent = Object.entries(p)
          .filter(
            ([k]) =>
              ![
                "event",
                "time",
                "direction",
                "layer",
                "peer",
                "bytes",
                "packets_total",
                "bytes_total",
                "bytes_per_second",
                "seq",
                "at",
              ].includes(k),
          )
          .map(([k, v]) => `${k}=${v}`)
          .join("  ");
        row.append(pre);
      }
      fragment.append(row);
    }
    el.replaceChildren(fragment);
    if (nearEnd) el.scrollTop = el.scrollHeight;
  }
  let pollBusy = false,
    shownError = "";
  async function poll() {
    if (pollBusy || !state.ready) return;
    pollBusy = true;
    try {
      const s = await api("snapshot", state.seq);
      state.job = s.job;
      updateProfiles(s.profiles, s.selected);
      state.platform = s.platform;
      state.localAddresses = s.local_addresses || [];
      $("version").textContent = `Pingo ${s.version}`;
      $("permission-banner").hidden = s.elevated;
      $("elevate").hidden = s.platform !== "win32";
      if (s.platform !== "win32")
        $("permission-copy").textContent =
          "Launch Pingo with sudo/root for network actions. You can configure your connection now.";
      $("driver-label").hidden = s.platform !== "win32";
      $("interface-hint").hidden = s.platform !== "darwin";
      $("recovery-table-label").hidden = s.platform !== "linux";
      if (s.recovery_table && !$("recovery-table").value)
        $("recovery-table").value = s.recovery_table;
      state.missed += s.missed;
      addEvents(s.events);
      const tx = s.metrics["icmp:tx"] || {},
        rx = s.metrics["icmp:rx"] || {};
      $("metric-tx").textContent = bytes(tx.bytes_total);
      $("metric-rx").textContent = bytes(rx.bytes_total);
      $("metric-rate").textContent =
        `${bytes((tx.bytes_per_second || 0) + (rx.bytes_per_second || 0))}/s`;
      $("trace-retention").textContent =
        `Latest 120 packets · export up to 2,000 records.${state.missed ? ` ${state.missed} earlier records left the buffer.` : ""} Contains sensitive metadata.`;
      if (s.job.error) {
        const key = JSON.stringify(s.job.error) + state.errorSeq;
        if (shownError !== key) {
          toast(s.job.error.text, s.job.error.hint);
          shownError = key;
        }
      }
      if (s.job.action === "probe" && ["failed", "stopped"].includes(s.job.state))
        $("peer-test-result").textContent = s.job.state === "failed"
          ? "Peer test failed. Start Receive on the peer and review the activity log and network guidance."
          : "Peer test stopped; reachability was not verified.";
      renderControls();
    } catch (error) {
      toast("Desktop connection interrupted.", error.message);
    } finally {
      pollBusy = false;
    }
  }
  function showView(name) {
    state.view = name;
    document.body.dataset.view = name;
    document.querySelectorAll(".view").forEach((el) => {
      el.hidden = el.id !== `view-${name}`;
    });
    document.querySelectorAll("[data-view]").forEach((b) => {
      if (b.dataset.view === name) b.setAttribute("aria-current", "page");
      else b.removeAttribute("aria-current");
    });
    $("page-title").textContent = {
      direct: "Send & receive",
      vpn: "VPN tunnel",
      check: "Setup & recovery",
    }[name];
    $("page-description").textContent = {
      direct: "Send from one computer. Receive on the other.",
      vpn: "Connect both computers with the same key in VPN mode.",
      check: "Check this computer or restore network access.",
    }[name];
    renderControls();
  }
  function showTask(name, focus = false) {
    state.task = name;
    document.querySelectorAll("[data-task]").forEach((tab) => {
      const selected = tab.dataset.task === name;
      tab.setAttribute("aria-selected", selected);
      tab.tabIndex = selected ? 0 : -1;
      if (selected && focus) tab.focus();
      $(tab.getAttribute("aria-controls")).hidden = !selected;
    });
    $("message-form").hidden = name !== "message";
    renderControls();
  }
  function connectionDialog(edit = false) {
    const p = edit ? profile() : null;
    state.editing = p?.id || null;
    $("connection-form").reset();
    $("connection-form")
      .querySelectorAll("details")
      .forEach((details) => {
        details.open = false;
      });
    $("local-addresses").replaceChildren(
      ...state.localAddresses.map((ip) => new Option(ip)),
    );
    $("local-address-hint").textContent = state.localAddresses.length
      ? `Detected: ${state.localAddresses.join(", ")}. Pick the address reachable by your peer. 0.0.0.0 listens on all interfaces.`
      : "Enter your real IPv4 to export peer setup. 0.0.0.0 listens on all interfaces.";
    $("dialog-error").hidden = true;
    $("connection-dialog-title").textContent = p
      ? "Edit connection"
      : "Add a connection";
    const values = {
      "profile-name": p?.name || "My connection",
      "profile-peer": p?.peer || "",
      "profile-bind": p?.bind || "0.0.0.0",
      "profile-key": p?.key_file || "",
      "profile-folder": p?.receive_dir || "",
      "profile-timeout": p?.retry_seconds ?? 0.75,
      "profile-attempts": p?.attempts ?? 8,
      "profile-reconnects": p?.reconnects ?? 10,
      "profile-retention": (p?.resume_retention ?? 86400) / 3600,
      "profile-file-limit": (p?.max_file_bytes ?? 67108864) / 1048576,
      "profile-folder-limit": (p?.max_receive_bytes ?? 268435456) / 1048576,
    };
    Object.entries(values).forEach(([id, v]) => {
      $(id).value = v;
    });
    $("connection-dialog").showModal();
    $("profile-name").focus();
  }
  async function saveConnection() {
    const old = state.editing
      ? state.profiles.find((p) => p.id === state.editing)
      : {};
    const data = {
      ...old,
      name: $("profile-name").value.trim(),
      peer: $("profile-peer").value.trim(),
      bind: $("profile-bind").value.trim(),
      key_file: $("profile-key").value,
      retry_seconds: Number($("profile-timeout").value),
      attempts: Number($("profile-attempts").value),
      reconnects: Number($("profile-reconnects").value),
      resume_retention: Math.round(Number($("profile-retention").value) * 3600),
      max_file_bytes: Math.round(
        Number($("profile-file-limit").value) * 1048576,
      ),
      max_receive_bytes: Math.round(
        Number($("profile-folder-limit").value) * 1048576,
      ),
    };
    if (state.editing) data.id = state.editing;
    if ($("profile-folder").value.trim())
      data.receive_dir = $("profile-folder").value.trim();
    const saved = await api("save_connection", data);
    updateProfiles(
      [...state.profiles.filter((p) => p.id !== saved.id), saved],
      saved.id,
    );
    $("connection-dialog").close();
    toast(
      "Connection saved.",
      "Start Receive on one computer, then send from the other.",
      true,
    );
    await poll();
  }
  function loadVpn() {
    const p = profile();
    if (!p) return;
    $("vpn-role").value = p.vpn_listen ? "responder" : "client";
    $("vpn-address").value = p.address;
    $("vpn-routing").value = p.default_route
      ? "default"
      : p.routes.length
        ? "selected"
        : "subnet";
    $("vpn-routes").value = p.routes.join(", ");
    $("vpn-sources").value = p.allowed_source.join(", ");
    $("vpn-dns").value = p.dns.join(", ");
    $("vpn-driver").value = p.wintun_dll;
    $("vpn-interface").value = p.interface;
    $("vpn-kill").value =
      p.kill_switch === null ? "auto" : p.kill_switch ? "on" : "off";
    $("vpn-no-dns").checked = p.no_dns;
    routingChanged(false);
  }
  function routingChanged(adjust = true) {
    const responder = $("vpn-role").value === "responder";
    $("vpn-routing").querySelector('[value="default"]').disabled = responder;
    if (responder && $("vpn-routing").value === "default")
      $("vpn-routing").value = "subnet";
    if (responder) $("vpn-kill").value = "off";
    $("vpn-kill").disabled = responder;
    const def = $("vpn-routing").value === "default",
      selected = $("vpn-routing").value === "selected";
    $("routes-label").hidden = !selected;
    $("vpn-route-note").hidden = !def && !selected;
    $("connect-vpn").textContent = responder
      ? "Start VPN responder"
      : "Connect VPN";
    if (adjust && def && !$("vpn-sources").value.trim())
      $("vpn-sources").value = "0.0.0.0/0";
    $("vpn-dns").disabled = $("vpn-no-dns").checked;
  }
  async function start(kind, payload) {
    if (state.launching || state.job.running)
      throw { message: "Stop the current activity before starting another." };
    state.launching = true;
    renderControls();
    try {
      if (kind !== "unlock") {
        const checks = await refreshChecks();
        if (!checks)
          throw { message: "Local checks could not finish. Run setup check in Settings." };
        const failures = checks.filter((c) =>
          c.status === "fail" &&
          (kind === "vpn" || !c.name.includes("(VPN only)")) &&
          (kind === "listen" || !c.name.startsWith("Receive")),
        );
        if (failures.length) {
          showView("check");
          throw {
            message: "Fix the failed setup checks before starting.",
            hint: failures[0].detail,
          };
        }
      }
      if (kind === "probe")
        $("peer-test-result").textContent = "Testing the authenticated ICMP handshake…";
      await api("start", state.selected, kind, payload);
      state.job = { running: true, state: "starting", action: kind };
      shownError = "";
      $("toast").hidden = true;
      renderControls();
      await poll();
    } finally {
      state.launching = false;
      renderControls();
    }
  }
  function bind() {
    document.addEventListener("keydown", (event) => {
      if (
        !(event.ctrlKey || event.metaKey) ||
        event.altKey ||
        event.shiftKey ||
        event.isComposing ||
        $("connection-dialog").open
      )
        return;
      const views = { 1: "direct", 2: "vpn", 3: "check" };
      const view = views[event.key];
      const command = { n: "new-connection", o: "import-connection" }[
        event.key.toLowerCase()
      ];
      if (!view && !command) return;
      event.preventDefault();
      if (view) {
        showView(view);
        document.querySelector(`[data-view="${view}"]`).focus();
      } else if (!$(command).disabled) $(command).click();
    });
    document.querySelectorAll("[data-view]").forEach((b) => {
      b.onclick = () => showView(b.dataset.view);
    });
    const tabs = [...document.querySelectorAll("[data-task]")];
    tabs.forEach((tab, index) => {
      tab.onclick = () => showTask(tab.dataset.task);
      tab.onkeydown = (event) => {
        let next;
        if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
        if (event.key === "ArrowLeft")
          next = (index + tabs.length - 1) % tabs.length;
        if (event.key === "Home") next = 0;
        if (event.key === "End") next = tabs.length - 1;
        if (next === undefined) return;
        event.preventDefault();
        showTask(tabs[next].dataset.task, true);
      };
    });
    $("message").oninput = renderControls;
    $("message").onkeydown = (event) => {
      if (
        event.key === "Enter" &&
        (event.ctrlKey || event.metaKey) &&
        !event.isComposing
      ) {
        event.preventDefault();
        if (!$("send-message").disabled) $("message-form").requestSubmit();
      }
    };
    $("dismiss-toast").onclick = () => {
      $("toast").hidden = true;
    };
    $("new-connection").onclick = $("welcome-create").onclick = () =>
      connectionDialog();
    $("edit-connection").onclick = () => connectionDialog(true);
    $("close-dialog").onclick = () => $("connection-dialog").close();
    $("connection-form").onsubmit = (e) => {
      e.preventDefault();
      action($("save-connection"), saveConnection);
    };
    for (const [button, kind, input] of [
      ["choose-key", "key", "profile-key"],
      ["choose-folder", "folder", "profile-folder"],
      ["choose-driver", "driver", "vpn-driver"],
    ])
      $(button).onclick = () =>
        action($(button), async () => {
          const path = await api("choose", kind);
          if (path) $(input).value = path;
        });
    $("generate-key").onclick = () =>
      action($("generate-key"), async () => {
        if (
          $("profile-key").value &&
          !confirm(
            "Generate a different key? The other computer will also need this new key.",
          )
        )
          return;
        $("profile-key").value = await api("create_key");
      });
    $("connection-select").onchange = () =>
      action(null, async () => {
        await api("select_connection", $("connection-select").value);
        await poll();
      });
    $("import-connection").onclick = () =>
      action($("import-connection"), async () => {
        const path = await api("choose", "config");
        if (!path) return;
        await api("import_connection", path);
        await poll();
        toast(
          "Configuration imported.",
          "Both computers must use the same key. Run the setup check next.",
          true,
        );
      });
    $("pair-connection").onclick = () =>
      action($("pair-connection"), async () => {
        if (
          !confirm(
            "Create a folder containing the matching configuration and SECRET shared key? Transfer it to the other computer using a separate trusted channel.",
          )
        )
          return;
        const path = await api("export_pairing", state.selected);
        if (path)
          toast(
            "Other computer’s setup created.",
            `Transfer ${path} privately, then import peer.toml in Pingo on the other computer.`,
            true,
          );
      });
    $("choose-file").onclick = () =>
      action($("choose-file"), async () => {
        const path = await api("choose", "file");
        if (path) {
          state.file = path;
          $("file-name").textContent = path.split(/[\\/]/).pop();
          $("file-path").textContent = path;
        }
      });
    $("message-form").onsubmit = (e) => {
      e.preventDefault();
      action($("send-message"), async () => {
        await start("message", { text: $("message").value });
      });
    };
    $("send-file").onclick = () =>
      action($("send-file"), () => start("file", { path: state.file }));
    $("receive").onclick = () => action($("receive"), () => start("listen"));
    $("stop").onclick = () =>
      action($("stop"), async () => {
        await api("stop");
        await poll();
      });
    $("open-received").onclick = () =>
      action($("open-received"), () => api("open_received", state.selected));
    $("vpn-role").onchange = () => {
      const responder = $("vpn-role").value === "responder";
      if (["10.77.0.1/30", "10.77.0.2/30"].includes($("vpn-address").value))
        $("vpn-address").value = responder ? "10.77.0.2/30" : "10.77.0.1/30";
      routingChanged();
    };
    $("vpn-routing").onchange = () => routingChanged();
    $("vpn-no-dns").onchange = () => routingChanged(false);
    $("vpn-form").onsubmit = (e) => {
      e.preventDefault();
      action($("connect-vpn"), async () => {
        const p = profile();
        const def = $("vpn-routing").value === "default";
        const kill = $("vpn-kill").value;
        if (
          (def || kill === "on") &&
          !confirm(
            "This VPN can change routes and block outside traffic. " +
              (state.platform === "darwin"
                ? "The macOS kill switch also resets existing PF connections. "
                : "") +
              "If it fails, protection stays active; use Settings to restore connectivity. Continue?",
          )
        )
          return;
        const saved = await api("save_connection", {
          ...p,
          vpn_listen: $("vpn-role").value === "responder",
          address: $("vpn-address").value.trim(),
          interface: $("vpn-interface").value.trim(),
          default_route: def,
          routes:
            $("vpn-routing").value === "selected"
              ? list($("vpn-routes").value)
              : [],
          allowed_source: list($("vpn-sources").value),
          dns: $("vpn-no-dns").checked ? [] : list($("vpn-dns").value),
          no_dns: $("vpn-no-dns").checked,
          kill_switch: kill === "auto" ? null : kill === "on",
          wintun_dll: $("vpn-driver").value,
        });
        updateProfiles(
          state.profiles.map((item) => (item.id === saved.id ? saved : item)),
          saved.id,
        );
        await start("vpn");
      });
    };
    $("run-check").onclick = () => action($("run-check"), refreshChecks);
    $("review-checks").onclick = () => showView("check");
    $("test-peer").onclick = () => action($("test-peer"), () => start("probe"));
    $("unlock").onclick = () =>
      action($("unlock"), async () => {
        if (
          !confirm(
            "Remove Pingo’s retained protection and allow ordinary network traffic again?",
          )
        )
          return;
        await start("unlock", { table: $("recovery-table").value.trim() });
      });
    $("elevate").onclick = () => action($("elevate"), () => api("elevate"));
    $("trace-filter").onchange = $("show-hex").onchange = () => {
      renderTrace();
    };
    $("pause-trace").onclick = () => {
      state.paused = !state.paused;
      state.frozenPackets = state.paused ? state.packets.slice() : [];
      $("pause-trace").textContent = state.paused
        ? "Resume display"
        : "Pause display";
      $("pause-trace").setAttribute("aria-pressed", state.paused);
      renderTrace();
      renderControls();
    };
    $("export-trace").onclick = () =>
      action($("export-trace"), async () => {
        const path = await api("export_trace");
        if (path) toast("Recent trace exported.", path, true);
      });
  }
  async function ready() {
    if (state.ready) return;
    state.ready = true;
    await poll();
    setInterval(poll, 250);
  }
  document.addEventListener("DOMContentLoaded", () => {
    bind();
    renderControls();
    if (window.pywebview?.api) ready();
  });
  window.addEventListener("pywebviewready", ready);
})();
