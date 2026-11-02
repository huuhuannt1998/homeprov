/*
 * HOMEPROV E11 benign fixture (drafts/round13/E11_DESIGN.md, sections 2 and 5). An OSGi bundle in openHAB's addons
 * folder that plays the household's devices and the benign uses of the persistence API the design measures:
 *
 *   schedule      periodic state updates of the simulated sensors, posted on the event bus with this bundle as the
 *                 source, as bindings post them (period per item from /hpctl/fixture/schedule.json; pause/resume).
 *   set_state     one state update of one item (closure fixtures, warm-up).
 *   timeseries, remove_until  [Withheld from the artifact: how the bundle writes and removes persisted history (B-BACKFILL, B-REPLACE, B-RETAIN). See README.md, "What is deliberately not here".]
 *   rows          the item's persisted (time, state) pairs in a window, through the persistence extensions.
 *
 * Commands: /hpctl/fixture/cmd_<id>.json -> /hpctl/fixture/ack_<id>.json; every action is logged to actions.jsonl.
 */
package org.homeprov.e11.fixture;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.openhab.core.events.EventPublisher;
import org.openhab.core.items.Item;
import org.openhab.core.items.ItemRegistry;
import org.openhab.core.items.events.ItemEventFactory;
import org.openhab.core.persistence.HistoricItem;
import org.openhab.core.persistence.extensions.PersistenceExtensions;
import org.openhab.core.types.State;
import org.openhab.core.types.TimeSeries;
import org.openhab.core.types.TypeParser;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class Activator implements BundleActivator {
    static final String DIR = "/hpctl/fixture";
    static final String SERVICE = "jdbc";
    static final String SOURCE = "org.homeprov.e11.fixture";
    static final long VISIBLE_TIMEOUT_MS = 20000;

    private volatile boolean running;
    private volatile boolean paused = true;
    private Thread worker;
    private Thread ticker;
    private BundleContext ctx;
    private final Gson gson = new Gson();
    /** item -> {period_s, kind, lo, hi, values[]} from schedule.json; kind: walk | choice | toggle | counter */
    private volatile JsonObject schedule = new JsonObject();
    private final Map<String, Long> nextDue = new HashMap<>();
    private final Map<String, Double> walk = new HashMap<>();
    private Random rng = new Random(20261021L);

    @Override
    public void start(BundleContext context) {
        ctx = context;
        running = true;
        new File(DIR).mkdirs();
        worker = new Thread(this::loop, "homeprov-e11-fixture");
        worker.setDaemon(true);
        worker.start();
        ticker = new Thread(this::tick, "homeprov-e11-fixture-ticker");
        ticker.setDaemon(true);
        ticker.start();
        JsonObject ev = new JsonObject();
        ev.addProperty("ev", "start");
        log(ev);
    }

    @Override
    public void stop(BundleContext context) throws InterruptedException {
        running = false;
        for (Thread t : new Thread[] { worker, ticker }) {
            if (t != null) {
                t.interrupt();
                t.join(2000);
            }
        }
    }

    private <T> T service(Class<T> cls) {
        ServiceReference<T> ref = ctx.getServiceReference(cls);
        T s = ref == null ? null : ctx.getService(ref);
        if (s == null) {
            throw new IllegalStateException("service unavailable: " + cls.getName());
        }
        return s;
    }

    private static ZonedDateTime at(long ms) {
        return ZonedDateTime.ofInstant(Instant.ofEpochMilli(ms), ZoneOffset.UTC);
    }

    private Item item(String name) throws Exception {
        return service(ItemRegistry.class).getItem(name);
    }

    private State parse(Item it, String s) {
        State st = TypeParser.parseState(it.getAcceptedDataTypes(), s);
        if (st == null) {
            throw new IllegalArgumentException("state " + s + " not accepted by " + it.getName());
        }
        return st;
    }

    private void post(String itemName, String s) throws Exception {
        Item it = item(itemName);
        service(EventPublisher.class).post(ItemEventFactory.createStateEvent(itemName, parse(it, s), SOURCE));
    }

    // ------------------------------------------------------------------------------------------ periodic devices
    private void tick() {
        while (running) {
            try {
                Thread.sleep(250);
                if (paused) {
                    continue;
                }
                long now = System.currentTimeMillis();
                JsonObject sch = schedule;
                for (Map.Entry<String, JsonElement> e : sch.entrySet()) {
                    String name = e.getKey();
                    JsonObject c = e.getValue().getAsJsonObject();
                    long period = (long) (c.get("period_s").getAsDouble() * 1000);
                    long due = nextDue.getOrDefault(name, now + (long) (rng.nextDouble() * period));
                    if (now < due) {
                        nextDue.putIfAbsent(name, due);
                        continue;
                    }
                    nextDue.put(name, now + period);
                    post(name, nextValue(name, c));
                }
            } catch (InterruptedException ie) {
                return;
            } catch (Exception ex) {
                JsonObject ev = new JsonObject();
                ev.addProperty("ev", "tick_error");
                ev.addProperty("err", String.valueOf(ex));
                log(ev);
            }
        }
    }

    private String nextValue(String name, JsonObject c) {
        String kind = c.get("kind").getAsString();
        switch (kind) {
            case "walk": {
                double lo = c.get("lo").getAsDouble(), hi = c.get("hi").getAsDouble();
                double v = walk.getOrDefault(name, (lo + hi) / 2) + (rng.nextDouble() - 0.5) * (hi - lo) / 20;
                v = Math.max(lo, Math.min(hi, v));
                walk.put(name, v);
                String unit = c.has("unit") ? " " + c.get("unit").getAsString() : "";
                return String.format(java.util.Locale.ROOT, "%.2f", v) + unit;
            }
            case "counter": {
                double v = walk.getOrDefault(name, c.get("lo").getAsDouble()) + c.get("step").getAsDouble();
                walk.put(name, v);
                String unit = c.has("unit") ? " " + c.get("unit").getAsString() : "";
                return String.format(java.util.Locale.ROOT, "%.3f", v) + unit;
            }
            case "toggle": {
                JsonArray vals = c.getAsJsonArray("values");
                double i = walk.getOrDefault(name, 0.0) + 1;
                walk.put(name, i);
                return vals.get(((int) i) % vals.size()).getAsString();
            }
            default: { // choice
                JsonArray vals = c.getAsJsonArray("values");
                return vals.get(rng.nextInt(vals.size())).getAsString();
            }
        }
    }

    // ------------------------------------------------------------------------------------------------ commands
    private void loop() {
        while (running) {
            try {
                File[] cmds = new File(DIR).listFiles((d, n) -> n.startsWith("cmd_") && n.endsWith(".json"));
                if (cmds != null) {
                    Arrays.sort(cmds);
                    for (File f : cmds) {
                        handle(f);
                    }
                }
                Thread.sleep(200);
            } catch (InterruptedException e) {
                return;
            } catch (Exception e) {
                JsonObject ev = new JsonObject();
                ev.addProperty("ev", "loop_error");
                ev.addProperty("err", String.valueOf(e));
                log(ev);
            }
        }
    }

    private void handle(File f) {
        String name = f.getName();
        String cid = name.substring(4, name.length() - 5);
        JsonObject cmd;
        try {
            cmd = JsonParser.parseString(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8))
                    .getAsJsonObject();
        } catch (Exception e) {
            return;
        }
        f.delete();
        String op = cmd.has("op") ? cmd.get("op").getAsString() : "";
        JsonObject res;
        try {
            switch (op) {
                case "info": {
                    res = new JsonObject();
                    res.addProperty("ok", true);
                    res.addProperty("bundle", ctx.getBundle().getSymbolicName());
                    res.addProperty("paused", paused);
                    res.addProperty("tz", java.util.TimeZone.getDefault().getID());
                    break;
                }
                case "schedule": {
                    schedule = cmd.getAsJsonObject("items");
                    if (cmd.has("seed")) {
                        rng = new Random(cmd.get("seed").getAsLong());
                    }
                    nextDue.clear();
                    res = new JsonObject();
                    res.addProperty("ok", true);
                    res.addProperty("items", schedule.size());
                    break;
                }
                case "pause":
                case "resume": {
                    paused = "pause".equals(op);
                    res = new JsonObject();
                    res.addProperty("ok", true);
                    res.addProperty("paused", paused);
                    break;
                }
                case "set_state": {
                    post(cmd.get("item").getAsString(), cmd.get("state").getAsString());
                    res = new JsonObject();
                    res.addProperty("ok", true);
                    res.addProperty("t_post_ms", System.currentTimeMillis());
                    break;
                }
                case "timeseries":
                    res = timeseries(cmd);
                    break;
                case "remove_until":
                    res = removeUntil(cmd.get("item").getAsString(), cmd.get("until_ms").getAsLong());
                    break;
                case "rows":
                    res = rowsCmd(cmd.get("item").getAsString(), cmd.get("from_ms").getAsLong(),
                            cmd.get("to_ms").getAsLong());
                    break;
                default:
                    res = new JsonObject();
                    res.addProperty("ok", false);
                    res.addProperty("err", "unknown op " + op);
            }
        } catch (Exception e) {
            res = new JsonObject();
            res.addProperty("ok", false);
            res.addProperty("err", String.valueOf(e));
        }
        res.addProperty("op", op);
        res.addProperty("t_ack", System.currentTimeMillis() / 1000.0);
        JsonObject ev = res.deepCopy();
        ev.addProperty("ev", "action");
        ev.add("cmd", cmd);
        log(ev);
        try {
            File tmp = new File(DIR, ".ack_" + cid + ".tmp");
            Files.write(tmp.toPath(), gson.toJson(res).getBytes(StandardCharsets.UTF_8));
            Files.move(tmp.toPath(), new File(DIR, "ack_" + cid + ".json").toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            // the host times out
        }
    }

    /** Persisted (time ms, state) pairs of an item in [from, to), widened by a second for the DAO's text bounds. */
    private JsonArray rows(Item it, long fromMs, long toMs) {
        JsonArray out = new JsonArray();
        Iterable<HistoricItem> h = PersistenceExtensions.getAllStatesBetween(it, at(fromMs - 1000), at(toMs + 1000),
                SERVICE);
        if (h != null) {
            for (HistoricItem x : h) {
                long t = x.getTimestamp().toInstant().toEpochMilli();
                if (t >= fromMs && t < toMs) {
                    JsonArray p = new JsonArray();
                    p.add(t);
                    p.add(x.getState().toString());
                    out.add(p);
                }
            }
        }
        return out;
    }

    private JsonObject rowsCmd(String itemName, long fromMs, long toMs) throws Exception {
        JsonObject r = new JsonObject();
        r.addProperty("ok", true);
        r.add("rows", rows(item(itemName), fromMs, toMs));
        return r;
    }

    private JsonObject timeseries(JsonObject cmd) throws Exception {
        // [Withheld from the artifact: the code that writes a TimeSeries (past or future points) into the item's persisted history. See README.md, "What is deliberately not here".]
        throw new UnsupportedOperationException("withheld from the artifact");
    }

    private JsonObject removeUntil(String itemName, long untilMs) throws Exception {
        // [Withheld from the artifact: the code that removes the item's persisted history up to a time. See README.md, "What is deliberately not here".]
        throw new UnsupportedOperationException("withheld from the artifact");
    }

    private synchronized void log(JsonObject ev) {
        ev.addProperty("t", System.currentTimeMillis() / 1000.0);
        try (FileWriter w = new FileWriter(new File(DIR, "actions.jsonl"), StandardCharsets.UTF_8, true)) {
            w.write(gson.toJson(ev) + "\n");
        } catch (IOException e) {
            // best effort
        }
    }
}
