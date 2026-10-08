import com.sun.net.httpserver.*;
import java.io.*;
import java.math.BigDecimal;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Online Event Management System: Java web server + MySQL (JDBC).
 * 1) Load the database:  mysql -u root -p < event_management.sql
 * 2) Download MySQL Connector/J (mysql-connector-j-8.x.jar) from https://dev.mysql.com/downloads/connector/j/
 * 3) Run (Java 17+):
 *      Windows:    java -cp mysql-connector-j-8.4.0.jar EventAppMySQL.java
 *      Mac/Linux:  java -cp mysql-connector-j-8.4.0.jar EventAppMySQL.java
 *    Optional settings via environment variables: DB_URL, DB_USER, DB_PASS
 * 4) Open http://localhost:8080
 */
public class EventAppMySQL {
    static String env(String k, String d) { String v = System.getenv(k); return v == null ? d : v; }
    static final String URL = env("DB_URL", "jdbc:mysql://localhost:3306/event_mgmt?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
    static final String DB_USER = env("DB_USER", "root"), DB_PASS = env("DB_PASS", "");
    static final int PORT = Integer.parseInt(env("PORT", "8080"));
    // Google OAuth: set these as environment variables, never hard-code them here.
    static final String GOOGLE_CLIENT_ID = env("GOOGLE_CLIENT_ID", "");
    static final String GOOGLE_CLIENT_SECRET = env("GOOGLE_CLIENT_SECRET", "");
    static final String GOOGLE_REDIRECT_URI = env("GOOGLE_REDIRECT_URI", "http://localhost:" + env("PORT", "8080") + "/oauth/google/callback");
    // Minimal flat-JSON field reader (no library needed) — fine for Google's token/userinfo responses, which aren't nested.
    static String jsonStr(String json, String key) {
        var m = java.util.regex.Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }
    static {
        // Belt-and-suspenders: the driver should auto-register from the jar, but some launch setups miss it.
        try { Class.forName("com.mysql.cj.jdbc.Driver"); }
        catch (ClassNotFoundException e) { /* reported clearly in main() once we try to connect */ }
    }
    static final String[] ROLES = {"Admin", "Organizer", "Attendee"};
    static final Map<String, String[][]> NAV = Map.of(
        "Admin", new String[][]{{"users", "User management"}, {"approvals", "Event approvals"}, {"settings", "System settings"}, {"stats", "Event statistics"}, {"activity", "Activity monitor"}},
        "Organizer", new String[][]{{"events", "My events"}, {"tickets", "Ticket management"}, {"comm", "Attendee communication"}, {"stats", "Event statistics"}, {"upcoming", "Upcoming events"}},
        "Attendee", new String[][]{{"upcoming", "Upcoming events"}, {"browse", "Browse & register"}, {"tickets", "My tickets"}, {"updates", "Event updates"}, {"history", "Registration history"}, {"profile", "Profile"}});

    // ---------- database helpers (prepared statements only, so user input can't inject SQL) ----------
    static Connection conn() throws SQLException { return DriverManager.getConnection(URL, DB_USER, DB_PASS); }
    static List<Map<String, Object>> q(String sql, Object... p) throws SQLException {
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]);
            try (ResultSet rs = ps.executeQuery()) {
                ResultSetMetaData m = rs.getMetaData(); List<Map<String, Object>> out = new ArrayList<>();
                while (rs.next()) { Map<String, Object> r = new LinkedHashMap<>(); for (int i = 1; i <= m.getColumnCount(); i++) r.put(m.getColumnLabel(i), rs.getObject(i)); out.add(r); }
                return out;
            }
        }
    }
    static int upd(String sql, Object... p) throws SQLException {
        try (Connection c = conn(); PreparedStatement ps = c.prepareStatement(sql)) { for (int i = 0; i < p.length; i++) ps.setObject(i + 1, p[i]); return ps.executeUpdate(); }
    }
    static Object one(String sql, Object... p) throws SQLException { var r = q(sql, p); return r.isEmpty() ? null : r.get(0).values().iterator().next(); }
    /** Calls a stored procedure whose LAST parameter is an OUT value; returns that value as text. */
    static String call(String sql, Object... p) throws SQLException {
        try (Connection c = conn(); CallableStatement cs = c.prepareCall(sql)) {
            for (int i = 0; i < p.length; i++) cs.setObject(i + 1, p[i]);
            cs.registerOutParameter(p.length + 1, Types.VARCHAR); cs.execute(); return cs.getString(p.length + 1);
        }
    }
    // ---------- password storage: PBKDF2-HMAC-SHA256, random salt per user, stored as "iterations:saltB64:hashB64" ----------
    // Never store or compare raw passwords. The email itself is stored as plain text (it's an identifier, not a secret)
    // but is unique-constrained in the schema so two accounts can't share one.
    static final int PBKDF2_ITERATIONS = 120_000;
    static String hashPassword(String password) {
        byte[] salt = new byte[16]; new java.security.SecureRandom().nextBytes(salt);
        byte[] hash = pbkdf2(password.toCharArray(), salt, PBKDF2_ITERATIONS);
        return PBKDF2_ITERATIONS + ":" + Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
    }
    static boolean verifyPassword(String password, String stored) {
        try {
            String[] p = stored.split(":", 3);
            int iter = Integer.parseInt(p[0]);
            byte[] salt = Base64.getDecoder().decode(p[1]);
            byte[] expected = Base64.getDecoder().decode(p[2]);
            byte[] actual = pbkdf2(password.toCharArray(), salt, iter);
            if (actual.length != expected.length) return false;
            int diff = 0; for (int i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i]; // constant-time compare
            return diff == 0;
        } catch (Exception e) { return false; }
    }
    static byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
        try {
            var spec = new javax.crypto.spec.PBEKeySpec(password, salt, iterations, 256);
            return javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (Exception e) { throw new RuntimeException(e); }
    }
    static void log(int uid, String m) throws SQLException { upd("INSERT INTO activity_log(user_id,action) VALUES(?,?)", uid, m); }
    static String setting(String k, String d) throws SQLException { Object v = one("SELECT setting_value FROM system_settings WHERE setting_key=?", k); return v == null ? d : "" + v; }

    // ---------- small utilities ----------
    static String esc(String s) { return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"); }
    static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
    static int toInt(String s, int d) { try { return Integer.parseInt(s.trim()); } catch (Exception e) { return d; } }
    static int I(Object o) { if (o == null) return 0; if (o instanceof Boolean b) return b ? 1 : 0; return new BigDecimal("" + o).intValue(); }
    static String s(Map<String, Object> r, String k) { Object v = r.get(k); return v == null ? "" : "" + v; }
    static String money(Object o) { return o == null ? "0" : new BigDecimal("" + o).stripTrailingZeros().toPlainString(); }
    static String hm(Object t) { String x = "" + t; return x.length() >= 5 ? x.substring(0, 5) : x; }
    static String dt(Object t) { String x = "" + t; return x.length() >= 16 ? x.substring(0, 16) : x; }
    static Map<String, String> parse(String s) {
        Map<String, String> m = new HashMap<>(); if (s == null || s.isEmpty()) return m;
        for (String p : s.split("&")) { String[] kv = p.split("=", 2); m.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : ""); }
        return m;
    }
    static String hid(String n, Object v) { return "<input type=hidden name=" + n + " value='" + esc("" + v) + "'>"; }
    static String in(String n, String ph, String v) { return "<input name=" + n + " placeholder='" + esc(ph) + "' aria-label='" + esc(ph) + "' value='" + esc(v) + "' required>"; }
    static String inT(String n, String type, String v) { return "<input name=" + n + " type=" + type + " aria-label=" + n + " value='" + esc(v) + "' required>"; }
    static String nin(String n, String ph, Object v) { return "<input name=" + n + " type=number min=0 placeholder='" + esc(ph) + "' aria-label='" + esc(ph) + "' value='" + money(v) + "' required style='width:100px'>"; }
    static String sel(String n, String[] opts, String cur) {
        StringBuilder b = new StringBuilder("<select name=" + n + ">");
        for (String o : opts) b.append("<option ").append(o.equals(cur) ? "selected" : "").append(">").append(esc(o)).append("</option>");
        return b + "</select>";
    }
    static String btn(String a, String label) { return btn(a, label, ""); }
    static String btn(String a, String label, String cls) { return "<button class='btn " + cls + "' name=a value=" + a + (cls.equals("bad") ? " formnovalidate onclick=\"return confirm('Are you sure?')\"" : "") + ">" + label + "</button>"; }
    static String row(String v, String inner) { return "<form class=row method=post action=/act>" + hid("v", v) + inner + "</form>"; }
    static String tag(String s) { return "<span class='tag " + s + "'>" + s + "</span>"; }
    static String bars(List<Object[]> rows) {
        int max = 1; for (Object[] r : rows) max = Math.max(max, (int) r[1]);
        StringBuilder b = new StringBuilder();
        for (Object[] r : rows) b.append("<div class=bar><span>").append(esc((String) r[0])).append("</span><i style='width:").append((int) r[1] * 100 / max).append("%'></i><b>").append(r[1]).append("</b></div>");
        return b.toString();
    }
    static String shortT(String t) { String[] w = t.split(" "); return w.length > 1 ? w[0] + " " + w[1] : t; }
    static String empty(boolean none, String what) { return none ? "<p class=mut>" + what + "</p>" : ""; }

    // ---------- views (every screen reads from MySQL) ----------
    static String view(Map<String, Object> me, String v) throws SQLException {
        int uid = I(me.get("id")); String cur = setting("currency", "INR");
        return switch (s(me, "role") + "." + v) {
            case "Admin.users" -> users();
            case "Admin.approvals" -> approvals();
            case "Admin.settings" -> settings();
            case "Admin.stats" -> stats(true, uid, cur);
            case "Admin.activity" -> activity();
            case "Organizer.events" -> orgEvents(uid);
            case "Organizer.tickets" -> orgTickets(uid, cur);
            case "Organizer.comm" -> comm(uid);
            case "Organizer.stats" -> stats(false, uid, cur);
            case "Organizer.upcoming" -> upcoming(false, uid);
            case "Attendee.upcoming" -> upcoming(true, uid);
            case "Attendee.browse" -> browse(uid, cur);
            case "Attendee.tickets" -> myTickets(uid, cur);
            case "Attendee.updates" -> attUpdates(uid);
            case "Attendee.history" -> history(uid);
            case "Attendee.profile" -> profile(uid);
            default -> "";
        };
    }
    static String titleOptions() throws SQLException {
        StringBuilder b = new StringBuilder("<select name=title>");
        for (var t : q("SELECT title,level FROM role_titles ORDER BY level IS NULL, level DESC"))
            b.append("<option>").append(esc(s(t, "title"))).append(t.get("level") == null ? "" : " (level " + t.get("level") + ")").append("</option>");
        return b + "</select>";
    }
    static String stripLevel(String t) { return t.replaceAll("\\s*\\(level \\d+\\)$", ""); }
    static String users() throws SQLException {
        StringBuilder b = new StringBuilder("<h1>User management</h1><p class=mut>Admin-tier titles are ranked \u2014 level 6 is highest.</p><div class=card><h3>Add user</h3>"
            + row("users", in("name", "Name", "") + in("email", "Email", "") + "<label>Title " + titleOptions() + "</label>" + btn("adm.addUser", "Add user")) + "</div><div class=card>");
        for (var u : q("SELECT u.id,u.name,u.email,u.title,rt.level FROM users u JOIN role_titles rt ON rt.title=u.title ORDER BY u.id")) {
            StringBuilder sel = new StringBuilder("<select name=title>");
            for (var t : q("SELECT title,level FROM role_titles ORDER BY level IS NULL, level DESC"))
                sel.append("<option ").append(s(t, "title").equals(s(u, "title")) ? "selected" : "").append(">").append(esc(s(t, "title"))).append(t.get("level") == null ? "" : " (level " + t.get("level") + ")").append("</option>");
            sel.append("</select>");
            b.append(row("users", hid("id", u.get("id")) + in("name", "Name", s(u, "name")) + in("email", "Email", s(u, "email")) + "<label>Title " + sel + "</label>"
                + (u.get("level") != null ? "<span class=tag pending>Lv " + I(u.get("level")) + "</span>" : "") + btn("adm.saveUser", "Save") + btn("adm.delUser", "Delete", "bad")));
        }
        return b + "</div>";
    }
    static String approvals() throws SQLException {
        StringBuilder b = new StringBuilder("<h1>Event approvals</h1><div class=card>");
        for (var e : q("SELECT e.id,e.title,e.event_date,e.venue,e.status,u.name org FROM events e JOIN users u ON u.id=e.organizer_id ORDER BY e.status='pending' DESC, e.event_date"))
            b.append(row("approvals", hid("id", e.get("id")) + "<b>" + esc(s(e, "title")) + "</b><span class=mut>" + s(e, "event_date") + " · " + esc(s(e, "venue")) + " · by " + esc(s(e, "org")) + "</span>" + tag(s(e, "status"))
                + (s(e, "status").equals("pending") ? btn("adm.approve", "Approve") + btn("adm.reject", "Reject", "bad") : "")));
        return b + "</div>";
    }
    static String settings() throws SQLException {
        return "<h1>System settings</h1><div class=card>" + row("settings",
            "<label>Site name " + in("site", "Site name", setting("site_name", "Gatherly")) + "</label><label>Currency " + in("cur", "Currency", setting("currency", "INR")) + "</label>"
            + "<label>Platform fee % " + nin("fee", "Fee", setting("platform_fee_percent", "5")) + "</label><label>Event approval " + sel("approval", new String[]{"Required", "Automatic"}, setting("event_approval", "Required")) + "</label>"
            + btn("adm.saveSettings", "Save settings")) + "</div>";
    }
    static String activity() throws SQLException {
        StringBuilder b = new StringBuilder("<h1>Activity monitor</h1><p class=mut>Live from the database: refreshes every 5 seconds.</p><div class=card>");
        for (var a : q("SELECT a.created_at,COALESCE(u.name,'System') n,a.action FROM activity_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 50"))
            b.append("<div class=item><span class=mut>" + dt(a.get("created_at")) + "</span> &nbsp; <b>" + esc(s(a, "n")) + "</b>: " + esc(s(a, "action")) + "</div>");
        return b + "</div>";
    }
    static String stats(boolean admin, int uid, String cur) throws SQLException {
        var l = admin ? q("SELECT * FROM v_event_stats WHERE status='approved'") : q("SELECT * FROM v_event_stats WHERE organizer_id=?", uid);
        int sold = 0, rev = 0; List<Object[]> reg = new ArrayList<>(), sales = new ArrayList<>();
        StringBuilder t = new StringBuilder("<div class=tw><table><tr><th>Event<th>Capacity<th>Sold<th>Revenue</tr>");
        for (var e : l) { int sd = I(e.get("tickets_sold")), rv = I(e.get("revenue")); sold += sd; rev += rv;
            reg.add(new Object[]{shortT(s(e, "title")), sd}); sales.add(new Object[]{shortT(s(e, "title")), rv});
            t.append("<tr><td>" + esc(s(e, "title")) + "<td>" + I(e.get("capacity")) + "<td>" + sd + "<td>" + cur + " " + rv + "</tr>"); }
        String fee = admin ? " (platform fee " + setting("platform_fee_percent", "0") + "%: " + cur + " " + rev * toInt(setting("platform_fee_percent", "0"), 0) / 100 + ")" : "";
        String age = "";
        if (!admin) { List<Object[]> g = new ArrayList<>();
            for (var r : q("SELECT COALESCE(up.age_group,'Unknown') g,COUNT(*) n FROM registrations r JOIN events e ON e.id=r.event_id LEFT JOIN user_profiles up ON up.user_id=r.user_id WHERE e.organizer_id=? AND r.status='Registered' GROUP BY g", uid)) g.add(new Object[]{s(r, "g"), I(r.get("n"))});
            age = "<div class=card><h3>Attendee age groups</h3>" + bars(g) + "</div>"; }
        return "<h1>Event statistics</h1><div class=grid><div class=card><div class=stat>" + l.size() + "</div><span class=mut>Live events</span></div><div class=card><div class=stat>" + sold
            + "</div><span class=mut>Tickets sold</span></div><div class=card><div class=stat>" + cur + " " + rev + "</div><span class=mut>Ticket revenue" + fee + "</span></div></div>"
            + "<div class=grid><div class=card><h3>Tickets sold by event</h3>" + bars(reg) + "</div><div class=card><h3>Revenue (" + cur + ")</h3>" + bars(sales) + "</div>" + age + "</div><div class=card>" + t + "</table></div>";
    }
    static String orgEvents(int uid) throws SQLException {
        StringBuilder b = new StringBuilder("<h1>My events</h1><div class=card><h3>Create event</h3>" + row("events",
            in("title", "Title", "") + in("desc", "Description", "") + inT("date", "date", "") + inT("time", "time", "") + in("venue", "Venue", "") + nin("price", "Ticket price", 0) + nin("qty", "Tickets available", 100) + btn("org.addEvent", "Create event")) + "</div><div class=card>");
        for (var e : q("SELECT id,title,description,event_date,event_time,venue,status FROM events WHERE organizer_id=? ORDER BY event_date", uid))
            b.append(row("events", hid("id", e.get("id")) + in("title", "Title", s(e, "title")) + in("desc", "Description", s(e, "description")) + inT("date", "date", s(e, "event_date")) + inT("time", "time", hm(e.get("event_time"))) + in("venue", "Venue", s(e, "venue"))
                + tag(s(e, "status")) + btn("org.saveEvent", "Update") + btn("org.delEvent", "Delete", "bad")));
        return b + "</div>" + empty(false, "");
    }
    static String orgTickets(int uid, String cur) throws SQLException {
        StringBuilder b = new StringBuilder("<h1>Ticket management</h1><div class=card>");
        for (var e : q("SELECT e.id,e.title,t.price,t.quantity,(SELECT COALESCE(SUM(quantity),0) FROM ticket_purchases WHERE event_id=e.id) sold FROM events e JOIN tickets t ON t.event_id=e.id WHERE e.organizer_id=?", uid))
            b.append(row("tickets", hid("id", e.get("id")) + "<b style='min-width:180px'>" + esc(s(e, "title")) + "</b><label>Price " + nin("price", "Price", e.get("price")) + "</label><label>Quantity " + nin("qty", "Quantity", e.get("quantity"))
                + "</label><span class=mut>" + I(e.get("sold")) + " sold · " + cur + " " + I(e.get("sold")) * I(e.get("price")) + "</span>" + btn("org.saveTix", "Update tickets")));
        return b + "</div>";
    }
    static String comm(int uid) throws SQLException {
        StringBuilder o = new StringBuilder("<select name=eid>");
        for (var e : q("SELECT id,title FROM events WHERE organizer_id=? AND status='approved'", uid)) o.append("<option value=" + e.get("id") + ">" + esc(s(e, "title")) + "</option>");
        return "<h1>Attendee communication</h1><div class=card>" + row("comm", o + "</select><textarea name=msg rows=3 placeholder='Schedule change, reminder or welcome note' required style='flex:1;min-width:260px'></textarea>" + btn("org.send", "Send message")) + "</div>";
    }
    static String upcoming(boolean att, int uid) throws SQLException {
        var l = att ? q("SELECT e.title,e.event_date,e.event_time,e.venue FROM events e JOIN registrations r ON r.event_id=e.id AND r.user_id=? AND r.status='Registered' WHERE e.status='approved' AND e.event_date>=CURDATE() ORDER BY e.event_date,e.event_time", uid)
                    : q("SELECT title,event_date,event_time,venue FROM events WHERE organizer_id=? AND status='approved' AND event_date>=CURDATE() ORDER BY event_date,event_time", uid);
        StringBuilder b = new StringBuilder("<h1>Upcoming events</h1><div class=card>");
        for (var e : l) b.append("<div class=item><b>" + esc(s(e, "title")) + "</b><br><span class=mut>" + s(e, "event_date") + " at " + hm(e.get("event_time")) + " · " + esc(s(e, "venue")) + "</span></div>");
        return b + empty(l.isEmpty(), att ? "You haven't registered for any upcoming events yet." : "No upcoming events.") + "</div>";
    }
    static String browse(int uid, String cur) throws SQLException {
        StringBuilder b = new StringBuilder("<h1>Browse & register</h1><div class=grid>");
        for (var e : q("SELECT e.id,e.title,e.description,e.event_date,e.event_time,e.venue,t.price,t.quantity-COALESCE((SELECT SUM(quantity) FROM ticket_purchases WHERE event_id=e.id),0) remaining,"
            + "EXISTS(SELECT 1 FROM registrations r WHERE r.event_id=e.id AND r.user_id=? AND r.status='Registered') reg FROM events e JOIN tickets t ON t.event_id=e.id WHERE e.status='approved' AND e.event_date>=CURDATE() ORDER BY e.event_date", uid)) {
            boolean paid = new BigDecimal("" + e.get("price")).signum() > 0;
            b.append("<div class=card><h3>" + esc(s(e, "title")) + "</h3><p class=mut>" + esc(s(e, "description")) + "</p><p>" + s(e, "event_date") + " at " + hm(e.get("event_time")) + "<br>" + esc(s(e, "venue")) + "</p><p><b>" + (paid ? cur + " " + money(e.get("price")) : "Free")
                + "</b> <span class=mut>· " + I(e.get("remaining")) + " left</span></p>"
                + (I(e.get("reg")) == 1 ? tag("Registered") : row("browse", hid("eid", e.get("id")) + btn("att.register", "Register", "ghost")))
                + row("browse", hid("eid", e.get("id")) + nin("n", "Tickets", 1) + (paid ? "<input name=card placeholder='Card number' aria-label='Card number'>" : "") + btn("att.buy", "Buy tickets")) + "</div>");
        }
        return b + "</div>";
    }
    static String myTickets(int uid, String cur) throws SQLException {
        StringBuilder b = new StringBuilder("<h1>My tickets</h1><div class=card><div class=tw><table><tr><th>Event<th>Date<th>Tickets<th>Total paid</tr>");
        for (var t : q("SELECT * FROM v_attendee_tickets WHERE user_id=? ORDER BY purchased_at DESC", uid)) b.append("<tr><td>" + esc(s(t, "title")) + "<td>" + s(t, "event_date") + "<td>" + s(t, "quantity") + "<td>" + cur + " " + money(t.get("total_amount")) + "</tr>");
        return b + "</table></div></div>";
    }
    static String attUpdates(int uid) throws SQLException {
        StringBuilder b = new StringBuilder("<h1>Event updates</h1><div class=card>");
        if (I(one("SELECT COALESCE((SELECT receive_updates FROM user_profiles WHERE user_id=?),TRUE)", uid)) == 0) return b + "<p class=mut>Updates are off. Turn them on in your profile.</p></div>";
        var l = q("SELECT e.title,u.message,u.created_at FROM event_updates u JOIN events e ON e.id=u.event_id JOIN registrations r ON r.event_id=u.event_id AND r.user_id=? AND r.status='Registered' ORDER BY u.created_at DESC", uid);
        for (var u : l) b.append("<div class=item><b>" + esc(s(u, "title")) + "</b> <span class=mut>" + dt(u.get("created_at")) + "</span><br>" + esc(s(u, "message")) + "</div>");
        return b + empty(l.isEmpty(), "No updates yet.") + "</div>";
    }
    static String history(int uid) throws SQLException {
        StringBuilder b = new StringBuilder("<h1>Registration history</h1><div class=card><div class=tw><table><tr><th>Event<th>Registered on<th>Status</tr>");
        for (var r : q("SELECT e.title,r.registered_at,r.status FROM registrations r JOIN events e ON e.id=r.event_id WHERE r.user_id=? ORDER BY r.registered_at DESC", uid)) b.append("<tr><td>" + esc(s(r, "title")) + "<td>" + dt(r.get("registered_at")) + "<td>" + tag(s(r, "status")) + "</tr>");
        return b + "</table></div></div>";
    }
    static String profile(int uid) throws SQLException {
        var p = q("SELECT u.name,u.email,p.phone,p.city,COALESCE(p.receive_updates,TRUE) ru FROM users u LEFT JOIN user_profiles p ON p.user_id=u.id WHERE u.id=?", uid).get(0);
        return "<h1>Profile</h1><div class=card>" + row("profile", "<label>Name " + in("name", "Name", s(p, "name")) + "</label><label>Email " + in("email", "Email", s(p, "email")) + "</label><label>Phone " + in("phone", "Phone", s(p, "phone")) + "</label><label>City " + in("city", "City", s(p, "city"))
            + "</label><label>Send me event updates " + sel("updates", new String[]{"Yes", "No"}, I(p.get("ru")) == 1 ? "Yes" : "No") + "</label>" + btn("att.saveProfile", "Save profile")) + "</div>";
    }

    // ---------- actions: form input goes into MySQL; each returns a confirmation message ----------
    static String act(Map<String, Object> me, Map<String, String> f) {
        try { return doAct(me, f); }
        catch (SQLIntegrityConstraintViolationException e) { return "That email is already in use"; }
        catch (SQLException e) { e.printStackTrace(); return "Database error: " + e.getMessage(); }
    }
    static String doAct(Map<String, Object> me, Map<String, String> f) throws SQLException {
        String a = f.getOrDefault("a", ""), role = s(me, "role"); int uid = I(me.get("id"));
        if (!a.startsWith(role.substring(0, 3).toLowerCase() + ".")) return "That action isn't available for your role";
        switch (a) {
            case "adm.addUser": {
                String title = stripLevel(f.get("title"));
                upd("INSERT INTO users(name,email,password_hash,title,role) SELECT ?,?,?,?,dashboard_role FROM role_titles WHERE title=?", f.get("name"), f.get("email"), "CHANGE_ME", title, title);
                log(uid, "Created user " + f.get("name") + " as " + title); return "User created"; }
            case "adm.saveUser": {
                String title = stripLevel(f.get("title"));
                upd("UPDATE users u JOIN role_titles rt ON rt.title=? SET u.name=?,u.email=?,u.title=?,u.role=rt.dashboard_role WHERE u.id=?", title, f.get("name"), f.get("email"), title, toInt(f.get("id"), 0));
                log(uid, "Updated user " + f.get("name") + " to " + title); return "User updated"; }
            case "adm.delUser": if (toInt(f.get("id"), 0) == uid) return "You can't delete your own account"; upd("DELETE FROM users WHERE id=?", toInt(f.get("id"), 0)); log(uid, "Deleted user #" + f.get("id")); return "User deleted";
            case "adm.approve": upd("CALL sp_review_event(?,?,?)", uid, toInt(f.get("id"), 0), "approved"); return "Event approved";
            case "adm.reject": upd("CALL sp_review_event(?,?,?)", uid, toInt(f.get("id"), 0), "rejected"); return "Event rejected";
            case "adm.saveSettings":
                for (String[] k : new String[][]{{"site", "site_name"}, {"cur", "currency"}, {"fee", "platform_fee_percent"}, {"approval", "event_approval"}})
                    upd("INSERT INTO system_settings(setting_key,setting_value) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)", k[1], f.get(k[0]));
                log(uid, "System settings updated"); return "Settings updated";
            case "org.addEvent": {
                String tm = f.get("time"); if (tm.length() == 5) tm += ":00";
                upd("CALL sp_create_event(?,?,?,?,?,?,?,?)", uid, f.get("title"), f.get("desc"), java.sql.Date.valueOf(f.get("date")), Time.valueOf(tm), f.get("venue"), new BigDecimal(f.get("price")), toInt(f.get("qty"), 100));
                return "Event created" + (setting("event_approval", "Required").equals("Required") ? ". It will be visible once an admin approves it." : "."); }
            case "org.saveEvent": {
                String tm = f.get("time"); if (tm.length() == 5) tm += ":00";
                return upd("UPDATE events SET title=?,description=?,event_date=?,event_time=?,venue=? WHERE id=? AND organizer_id=?", f.get("title"), f.get("desc"), java.sql.Date.valueOf(f.get("date")), Time.valueOf(tm), f.get("venue"), toInt(f.get("id"), 0), uid) > 0 ? "Event updated" : "Event not found"; }
            case "org.delEvent": return upd("DELETE FROM events WHERE id=? AND organizer_id=?", toInt(f.get("id"), 0), uid) > 0 ? "Event deleted" : "Event not found";
            case "org.saveTix": {
                int id = toInt(f.get("id"), 0), qty = toInt(f.get("qty"), 0), sold = I(one("SELECT COALESCE(SUM(quantity),0) FROM ticket_purchases WHERE event_id=?", id));
                if (qty < sold) return "Quantity can't be below the " + sold + " tickets already sold";
                return upd("UPDATE tickets t JOIN events e ON e.id=t.event_id SET t.price=?,t.quantity=? WHERE t.event_id=? AND e.organizer_id=?", new BigDecimal(f.get("price")), qty, id, uid) > 0 ? "Tickets updated" : "Event not found"; }
            case "org.send": {
                int eid = toInt(f.get("eid"), 0);
                if (one("SELECT id FROM events WHERE id=? AND organizer_id=?", eid, uid) == null) return "Pick one of your events first";
                return "Message delivered to " + call("{call sp_send_update(?,?,?,?)}", uid, eid, f.get("msg")) + " registered attendee(s)"; }
            case "att.register": return call("{call sp_register(?,?,?)}", uid, toInt(f.get("eid"), 0));
            case "att.buy": {
                int eid = toInt(f.get("eid"), 0); Object price = one("SELECT price FROM tickets WHERE event_id=?", eid);
                if (price == null) return "Event not found";
                if (new BigDecimal("" + price).signum() > 0 && f.getOrDefault("card", "").replaceAll("\\D", "").length() < 12) return "Enter a valid card number";
                // Card details are never stored: only a payment reference is saved (replace with your payment gateway's transaction id).
                return call("{call sp_buy_tickets(?,?,?,?,?)}", uid, eid, toInt(f.get("n"), 0), "demo-" + System.currentTimeMillis()); }
            case "att.saveProfile":
                upd("UPDATE users SET name=?,email=? WHERE id=?", f.get("name"), f.get("email"), uid);
                upd("INSERT INTO user_profiles(user_id,phone,city,receive_updates) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE phone=VALUES(phone),city=VALUES(city),receive_updates=VALUES(receive_updates)", uid, f.get("phone"), f.get("city"), f.get("updates").equals("Yes"));
                return "Profile saved";
            default: return "Unknown action";
        }
    }

    // ---------- page shell ----------
    static final String CSS = """
        :root{--bg:#f2f5f6;--card:#fff;--ink:#10242a;--mut:#5d7278;--line:#dbe4e6;--pri:#14808a;--bad:#c23a3a;--ok:#1f8a4c;--warn:#b7791f}
        @media(prefers-color-scheme:dark){:root{--bg:#0d1a1e;--card:#15272c;--ink:#e6eff1;--mut:#8ea5ab;--line:#26393f;--pri:#2fb3bf;--bad:#ef7373;--ok:#4cc783;--warn:#e0a94f}}
        *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
        h1{font-size:26px;margin:0 0 14px}h3{margin:0 0 8px}a{color:inherit}
        .app{display:grid;grid-template-columns:230px 1fr;min-height:100vh}
        aside{background:#10242a;padding:18px 12px;display:flex;flex-direction:column;gap:4px}aside b{color:#fff;font-size:20px;padding:0 10px 14px}
        aside a{color:#b6c8cc;text-decoration:none;padding:9px 10px;border-radius:8px}aside a.on,aside a:hover{background:rgba(255,255,255,.1);color:#fff}
        main{padding:26px;min-width:0}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
        .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
        .row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:8px 0;border-bottom:1px solid var(--line)}.card>.row:last-child{border:0}
        input,select,textarea{padding:7px 9px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);font:inherit}
        .btn{background:var(--pri);color:#fff;border:0;border-radius:8px;padding:8px 14px;cursor:pointer;font-weight:600}.btn.ghost{background:none;color:var(--ink);border:1px solid var(--line)}.btn.bad{background:var(--bad)}
        .tag{padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;background:var(--line)}.tag.approved,.tag.Registered{color:var(--ok)}.tag.pending{color:var(--warn)}.tag.rejected,.tag.Cancelled{color:var(--bad)}
        .mut{color:var(--mut);font-size:13px}.stat{font-size:30px;font-weight:700}.item{padding:9px 0;border-bottom:1px solid var(--line)}
        .bar{display:grid;grid-template-columns:110px 1fr 60px;gap:8px;align-items:center;font-size:13px;margin:7px 0}.bar i{display:block;height:12px;border-radius:6px;background:var(--pri)}
        .tw{overflow-x:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line)}
        .msg{background:var(--pri);color:#fff;padding:10px 14px;border-radius:10px;margin-bottom:14px}
        .login{max-width:720px;margin:10vh auto;padding:20px}.roles{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-top:20px}
        .roles a{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;text-decoration:none}.roles a:hover{border-color:var(--pri)}
        @media(max-width:760px){.app{grid-template-columns:1fr}main{padding:16px}}
        """;
    static String page(String site, String body, String head) {
        return "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>" + esc(site) + "</title>" + head + "<style>" + CSS + "</style></head><body>" + body + "</body></html>";
    }
    static String dash(Map<String, Object> me, String v, String msg) throws SQLException {
        String role = s(me, "role"); String[][] nav = NAV.get(role); String site = setting("site_name", "Gatherly");
        final String vv = Arrays.stream(nav).anyMatch(n -> n[0].equals(v)) ? v : nav[0][0];
        StringBuilder n = new StringBuilder("<aside><b>" + esc(site) + "</b>");
        for (String[] i : nav) n.append("<a class='" + (i[0].equals(vv) ? "on" : "") + "' href='/dash?v=" + i[0] + "'>" + i[1] + "</a>");
        Object titleObj = one("SELECT title FROM users WHERE id=?", I(me.get("id")));
        String title = titleObj == null ? "" : "" + titleObj;
        n.append("<span class=mut style='margin-top:auto;padding:10px'>" + esc(s(me, "name")) + " &middot; " + esc(title.isEmpty() ? role : title) + "<br><a href=/logout>Log out</a></span></aside>");
        String m = (msg == null || msg.isEmpty()) ? "" : "<div class=msg role=status>" + esc(msg) + "</div>";
        return page(site, "<div class=app>" + n + "<main>" + m + view(me, vv) + "</main></div>", vv.equals("activity") ? "<meta http-equiv=refresh content=5>" : "");
    }
    static String loginPage() throws SQLException { return loginPage(null); }
    static String loginPage(String err) throws SQLException {
        String site = setting("site_name", "Gatherly");
        StringBuilder b = new StringBuilder("<div class=login><h1 style='font-size:44px'>" + esc(site) + "</h1><p class=mut>Online Event Management System. Sign in with your email and password.</p>");
        if (err != null) b.append("<p class=msg style='background:var(--bad)'>" + esc(err) + "</p>");
        b.append("<p style='max-width:380px'><a class='btn ghost' href='/oauth/google' style='display:block;text-align:center;width:100%;box-sizing:border-box'>Continue with Google</a></p>");
        b.append("<form method=post action=/login style='max-width:380px'>"
            + "<label>Email<input name=email type=email required autofocus></label>"
            + "<label>Password<input name=pass type=password required></label>"
            + "<button class=btn style='width:100%;margin-top:10px;padding:10px'>Sign in</button></form>");
        b.append("<p class=mut style='margin-top:18px;font-size:13px'>Demo accounts (password shown for convenience only \u2014 real accounts should never display passwords):<br>");
        for (var u : q("SELECT u.email,u.title FROM users u WHERE u.is_active AND u.id<=3 ORDER BY u.id"))
            b.append(esc(s(u, "email"))).append(" &middot; ").append(esc(s(u, "title"))).append("<br>");
        b.append("ravi@gatherly.io / admin123 &nbsp; priya@summitco.com / organizer123 &nbsp; aisha@mail.com / attendee123</p>");
        b.append("<p class=mut style='margin-top:14px'>New here? <a href='/signup'>Create an account</a></p>");
        return page(site, b + "</div>", "");
    }
    static String signupPage(String err) {
        StringBuilder b = new StringBuilder("<div class=login><h1 style='font-size:36px'>Create your account</h1><p class=mut>Public sign-up is for attendees and organizers. Admin-tier titles are granted by an administrator in User management.</p>");
        if (err != null) b.append("<p class=msg style='background:var(--bad)'>" + esc(err) + "</p>");
        b.append("<form method=post action=/signup style='max-width:420px'>"
            + "<label>Full name<input name=name required></label><label>Email<input name=email type=email required></label>"
            + "<label>Password (min 6 characters)<input name=pass type=password minlength=6 required></label>"
            + "<label>I am a&hellip; <select name=title><option>Attendee</option><option>Organizer</option></select></label>"
            + "<div class=acts style='margin-top:14px'><a class='btn ghost' href='/'>Cancel</a><button class=btn>Create account</button></div></form></div>");
        return page("Sign up", b.toString(), "");
    }

    // ---------- HTTP ----------
    static Map<String, Object> userOf(HttpExchange x) throws SQLException {
        String c = x.getRequestHeaders().getFirst("Cookie");
        if (c != null) for (String p : c.split(";\\s*")) if (p.startsWith("uid=")) {
            var r = q("SELECT id,name,role FROM users WHERE id=? AND is_active", toInt(p.substring(4), -1));
            if (!r.isEmpty()) return r.get(0);
        }
        return null;
    }
    static void send(HttpExchange x, int code, String body, String loc, String cookie) throws IOException {
        byte[] out = body.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        if (loc != null) x.getResponseHeaders().set("Location", loc);
        if (cookie != null) x.getResponseHeaders().add("Set-Cookie", cookie);
        boolean noBody = code == 303 || code == 302;
        x.sendResponseHeaders(code, noBody ? -1 : out.length);
        if (!noBody) try (OutputStream o = x.getResponseBody()) { o.write(out); }
        x.close();
    }
    static void handle(HttpExchange x) throws IOException {
        try {
            String path = x.getRequestURI().getPath(); Map<String, String> qs = parse(x.getRequestURI().getRawQuery());
            if (path.equals("/logout")) { send(x, 303, "", "/", "uid=; Path=/; Max-Age=0"); return; }
            if (path.equals("/login") && x.getRequestMethod().equals("POST")) {
                Map<String, String> f = parse(new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                var rows = q("SELECT id,password_hash FROM users WHERE email=? AND is_active", f.getOrDefault("email", ""));
                if (!rows.isEmpty() && verifyPassword(f.getOrDefault("pass", ""), s(rows.get(0), "password_hash"))) {
                    int id = I(rows.get(0).get("id"));
                    send(x, 303, "", "/dash", "uid=" + id + "; Path=/; HttpOnly; SameSite=Lax"); return;
                }
                send(x, 200, loginPage("Email and password don't match"), null, null); return;
            }
            if (path.equals("/oauth/google")) {
                if (GOOGLE_CLIENT_ID.isEmpty()) { send(x, 200, loginPage("Google sign-in isn't configured on this server yet (missing GOOGLE_CLIENT_ID)."), null, null); return; }
                String authUrl = "https://accounts.google.com/o/oauth2/v2/auth?client_id=" + enc(GOOGLE_CLIENT_ID)
                    + "&redirect_uri=" + enc(GOOGLE_REDIRECT_URI) + "&response_type=code&scope=" + enc("openid email profile") + "&prompt=select_account";
                send(x, 302, "", authUrl, null); return;
            }
            if (path.equals("/oauth/google/callback")) {
                String code = qs.get("code");
                if (code == null) { send(x, 200, loginPage("Google sign-in was cancelled."), null, null); return; }
                HttpClient http = HttpClient.newHttpClient();
                String tokenBody = "code=" + enc(code) + "&client_id=" + enc(GOOGLE_CLIENT_ID) + "&client_secret=" + enc(GOOGLE_CLIENT_SECRET)
                    + "&redirect_uri=" + enc(GOOGLE_REDIRECT_URI) + "&grant_type=authorization_code";
                var tokenReq = HttpRequest.newBuilder(URI.create("https://oauth2.googleapis.com/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(tokenBody)).build();
                String tokenJson = http.send(tokenReq, HttpResponse.BodyHandlers.ofString()).body();
                String accessToken = jsonStr(tokenJson, "access_token");
                if (accessToken == null) { send(x, 200, loginPage("Google didn't return an access token. Check GOOGLE_CLIENT_SECRET and the redirect URI."), null, null); return; }
                var infoReq = HttpRequest.newBuilder(URI.create("https://openidconnect.googleapis.com/v1/userinfo")).header("Authorization", "Bearer " + accessToken).GET().build();
                String infoJson = http.send(infoReq, HttpResponse.BodyHandlers.ofString()).body();
                String email = jsonStr(infoJson, "email"), name = jsonStr(infoJson, "name");
                if (email == null) { send(x, 200, loginPage("Google didn't share an email address for this account."), null, null); return; }
                var existing = q("SELECT id FROM users WHERE email=?", email);
                int googleUid;
                if (!existing.isEmpty()) {
                    googleUid = I(existing.get(0).get("id"));
                } else {
                    // First time signing in with this Google account: create an Attendee with an unusable random password (they'll always use Google to sign in).
                    try (Connection c = conn(); CallableStatement cs = c.prepareCall("{call sp_signup(?,?,?,?,?,?)}")) {
                        cs.setString(1, name != null ? name : email); cs.setString(2, email); cs.setString(3, hashPassword(UUID.randomUUID().toString())); cs.setString(4, "Attendee");
                        cs.registerOutParameter(5, Types.INTEGER); cs.registerOutParameter(6, Types.VARCHAR); cs.execute();
                        googleUid = cs.getInt(5);
                        if (googleUid == 0) { send(x, 200, loginPage(cs.getString(6)), null, null); return; }
                        log(googleUid, "Signed up via Google");
                    }
                }
                send(x, 303, "", "/dash", "uid=" + googleUid + "; Path=/; HttpOnly; SameSite=Lax"); return;
            }
            if (path.equals("/signup") && x.getRequestMethod().equals("GET")) { send(x, 200, signupPage(null), null, null); return; }
            if (path.equals("/signup") && x.getRequestMethod().equals("POST")) {
                Map<String, String> f = parse(new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                if (f.getOrDefault("pass", "").length() < 6) { send(x, 200, signupPage("Password should be at least 6 characters"), null, null); return; }
                try (Connection c = conn(); CallableStatement cs = c.prepareCall("{call sp_signup(?,?,?,?,?,?)}")) {
                    cs.setString(1, f.get("name")); cs.setString(2, f.get("email")); cs.setString(3, hashPassword(f.get("pass"))); cs.setString(4, f.get("title"));
                    cs.registerOutParameter(5, Types.INTEGER); cs.registerOutParameter(6, Types.VARCHAR); cs.execute();
                    int newId = cs.getInt(5); String msg = cs.getString(6);
                    if (newId == 0) { send(x, 200, signupPage(msg), null, null); return; }
                    log(newId, msg); send(x, 303, "", "/dash", "uid=" + newId + "; Path=/; HttpOnly; SameSite=Lax"); return;
                }
            }
            Map<String, Object> me = userOf(x);
            if (me == null) { send(x, 200, loginPage(), null, null); return; }
            if (path.equals("/act") && x.getRequestMethod().equals("POST")) {
                Map<String, String> f = parse(new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                send(x, 303, "", "/dash?v=" + enc(f.getOrDefault("v", "")) + "&m=" + enc(act(me, f)), null); return;
            }
            send(x, 200, dash(me, qs.getOrDefault("v", ""), qs.get("m")), null, null);
        } catch (Exception e) {
            e.printStackTrace();
            String tip = e instanceof SQLException ? "Can't reach the database (" + esc(e.getMessage()) + "). Check that MySQL is running, event_management.sql is loaded, and DB_URL / DB_USER / DB_PASS are correct." : "Something went wrong.";
            send(x, 500, page("Error", "<div class=login><h1>Something went wrong</h1><p>" + tip + "</p><p><a href=/>Back to start</a></p></div>", ""), null, null);
        }
    }
    public static void main(String[] args) throws Exception {
        try (Connection c = conn()) { System.out.println("Connected to MySQL: " + URL); }
        catch (SQLException e) {
            String msg = e.getMessage();
            if (msg != null && msg.contains("No suitable driver")) {
                System.out.println("WARNING: the MySQL JDBC driver isn't on the classpath.");
                System.out.println("  Download mysql-connector-j-*.jar from https://dev.mysql.com/downloads/connector/j/");
                System.out.println("  and run with:  java -cp mysql-connector-j-*.jar EventAppMySQL.java");
                System.out.println("  (the -cp jar name must match the .jar file you actually downloaded)");
            } else {
                System.out.println("WARNING: cannot connect to MySQL yet (" + msg + "). Check DB_URL / DB_USER / DB_PASS, and that MySQL is running.");
            }
        }
        HttpServer s;
        try {
            s = HttpServer.create(new InetSocketAddress(PORT), 0);
        } catch (java.net.BindException be) {
            System.out.println("ERROR: port " + PORT + " is already in use \u2014 something else (maybe an earlier run of this app) is already listening there.");
            System.out.println("  Either stop that process, or run this one on a different port:");
            System.out.println("    Windows:    set PORT=8081 && java -cp mysql-connector-j-*.jar EventAppMySQL.java");
            System.out.println("    Mac/Linux:  PORT=8081 java -cp mysql-connector-j-*.jar EventAppMySQL.java");
            System.out.println("  To find what's using port " + PORT + ":");
            System.out.println("    Windows:    netstat -ano | findstr :" + PORT + "   (then taskkill /PID <pid> /F)");
            System.out.println("    Mac/Linux:  lsof -i :" + PORT + "   (then kill -9 <pid>, or: kill $(lsof -t -i:" + PORT + "))");
            return;
        }
        s.createContext("/", EventAppMySQL::handle);
        s.start();
        System.out.println("Event Management System running at http://localhost:" + PORT);
    }
}
