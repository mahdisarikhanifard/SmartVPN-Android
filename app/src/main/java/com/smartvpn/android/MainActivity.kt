package com.smartvpn.android

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.graphics.Typeface
import android.net.TrafficStats
import android.net.VpnService
import android.os.Bundle
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URI
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.UUID
import java.util.concurrent.Executors

private data class ServerEntry(
    val id: String,
    val name: String,
    val protocol: String,
    val host: String,
    val port: Int,
    val raw: String,
    var latencyMs: Long = -1
)

class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private val io = Executors.newFixedThreadPool(4)
    private val servers = mutableListOf<ServerEntry>()
    private var autoCandidates: List<ServerEntry> = emptyList()
    private var autoCandidateIndex = 0
    private var autoSourceIndex = 0
    private var autoSourceList: List<String> = emptyList()
    @Volatile private var autoConnecting = false
    private lateinit var root: LinearLayout
    private lateinit var statusView: TextView
    private lateinit var trafficView: TextView
    private lateinit var listView: LinearLayout
    private var previousRx = TrafficStats.getTotalRxBytes()
    private var previousTx = TrafficStats.getTotalTxBytes()

    private val trafficRefresh = object : Runnable {
        override fun run() {
            val rx = TrafficStats.getTotalRxBytes()
            val tx = TrafficStats.getTotalTxBytes()
            val down = if (rx >= 0 && previousRx >= 0) (rx - previousRx).coerceAtLeast(0) else 0
            val up = if (tx >= 0 && previousTx >= 0) (tx - previousTx).coerceAtLeast(0) else 0
            trafficView.text = "ترافیک کل دستگاه (نه ترافیک اختصاصی VPN)\nدریافت: ${formatRate(down)}   |   ارسال: ${formatRate(up)}"
            previousRx = rx
            previousTx = tx
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        loadServers()
        buildScreen()
        renderServers()
        handler.post(trafficRefresh)
    }

    private val vpnStatusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != SingBoxVpnService.ACTION_STATUS) return
            when (intent.getStringExtra("state")) {
                "connected" -> { autoConnecting = false; statusView.text = "وضعیت: VPN متصل و عبور اینترنت بررسی شد" }
                "disconnected" -> statusView.text = "وضعیت: اتصال VPN قطع است"
                "error" -> {
                    val message = intent.getStringExtra("error") ?: "نامشخص"
                    if (autoConnecting) tryNextAutoCandidate(message) else statusView.text = "خطای اتصال VPN: $message"
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(SingBoxVpnService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(vpnStatusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(vpnStatusReceiver, filter)
        }
        val running = getSharedPreferences(PREFS, MODE_PRIVATE).getBoolean("vpn_running", false)
        statusView.text = if (running) "وضعیت: VPN متصل است" else "وضعیت: VPN قطع است"
    }

    override fun onPause() {
        runCatching { unregisterReceiver(vpnStatusReceiver) }
        super.onPause()
    }
    private fun buildScreen() {
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = android.view.Gravity.CENTER_HORIZONTAL
            setPadding(28, 36, 28, 28)
            setBackgroundColor(Color.rgb(10, 21, 38))
        }
        fun label(value: String, size: Float, color: Int = Color.WHITE, bold: Boolean = false) =
            TextView(this).apply {
                text = value
                textSize = size
                setTextColor(color)
                gravity = android.view.Gravity.CENTER
                if (bold) setTypeface(null, Typeface.BOLD)
                setPadding(0, 10, 0, 10)
            }
        // Keep the legacy server-list container initialized even though the
        // simplified home screen no longer displays it.
        listView = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        root.addView(label("SmartVPN", 30f, Color.WHITE, true))
        root.addView(label("اتصال هوشمند و خودکار", 16f, Color.LTGRAY))
        statusView = label("آماده برای اتصال", 15f, Color.rgb(110, 220, 180), true)
        root.addView(statusView, matchWidth())
        root.addView(Button(this).apply {
            text = "اتصال"
            textSize = 22f
            minHeight = 76
            setOnClickListener { startAutoConnect() }
        }, matchWidth())
        addButton("قطع اتصال") { autoConnecting = false; stopVpn() }
        addButton("تنظیمات") { showSettings() }
        trafficView = label("ترافیک کل دستگاه (نه آمار اختصاصی VPN)\nدر حال اندازه‌گیری…", 12f, Color.LTGRAY)
        root.addView(trafficView, matchWidth())
        root.addView(label("برنامه منابع سرور را بررسی می‌کند، گزینه‌های قابل دسترس را می‌آزماید و بهترین گزینهٔ قابل استفاده را امتحان می‌کند.", 13f, Color.LTGRAY))
        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun showSettings() {
        val source = EditText(this).apply {
            hint = "نشانی اشتراک خودکار (HTTPS)"
            setText(getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_AUTO_SOURCE, DEFAULT_AUTO_SOURCE))
            textSize = 14f
        }
        val panel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 8, 24, 8)
            addView(TextView(this@MainActivity).apply {
                text = "منبع پیش‌فرض، فهرست عمومی و رایگان است؛ سرورها متعلق به اشخاص ثالث هستند و امنیت یا پایداری آن‌ها تضمین نمی‌شود."
                textSize = 13f
            })
            addView(source, matchWidth())
        }
        AlertDialog.Builder(this)
            .setTitle("تنظیمات اتصال")
            .setView(panel)
            .setPositiveButton("ذخیره منبع") { _, _ ->
                val value = source.text.toString().trim()
                if (value.startsWith("https://")) {
                    getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString(KEY_AUTO_SOURCE, value).apply()
                    toast("منبع اتصال خودکار ذخیره شد.")
                } else toast("نشانی منبع باید با HTTPS شروع شود.")
            }
            .setNeutralButton("مدیریت کانفیگ‌ها") { _, _ -> showConfigManagement() }
            .setNegativeButton("بستن", null)
            .show()
    }

    private fun showConfigManagement() {
        AlertDialog.Builder(this)
            .setTitle("مدیریت دستی سرورها")
            .setItems(arrayOf("افزودن لینک یا متن کانفیگ", "افزودن اشتراک HTTPS", "وارد کردن فایل / JSON", "نمایش و مدیریت سرورها", "آزمایش سرورهای ذخیره‌شده")) { _, which ->
                when (which) {
                    0 -> showTextImport()
                    1 -> showSubscriptionImport()
                    2 -> openConfigFile()
                    3 -> showSavedServers()
                    4 -> testAllServers()
                }
            }
            .setNegativeButton("بستن", null).show()
    }

    private fun showSavedServers() {
        if (servers.isEmpty()) { toast("هنوز کانفیگی ذخیره نشده است."); return }
        val labels = servers.map { "${it.name} — ${it.protocol} — ${it.host}:${it.port}" }.toTypedArray()
        AlertDialog.Builder(this).setTitle("سرورهای ذخیره‌شده")
            .setItems(labels) { _, which ->
                val selected = servers[which]
                AlertDialog.Builder(this).setMessage("سرور ${selected.name}")
                    .setPositiveButton("اتصال دستی") { _, _ -> autoConnecting = false; connectServer(selected) }
                    .setNeutralButton("حذف") { _, _ -> servers.remove(selected); saveServers(); showSavedServers() }
                    .setNegativeButton("بازگشت", null).show()
            }.setNegativeButton("بستن", null).show()
    }

    private fun matchWidth() = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)

    private fun addButton(title: String, action: () -> Unit) {
        root.addView(Button(this).apply {
            text = title
            setOnClickListener { action() }
        }, matchWidth())
    }

    private fun showTextImport() {
        val input = EditText(this).apply {
            hint = "لینک کانفیگ یا چند خط کانفیگ را وارد کنید"
            minLines = 3
        }
        AlertDialog.Builder(this)
            .setTitle("افزودن کانفیگ")
            .setView(input)
            .setPositiveButton("افزودن") { _, _ -> importText(input.text.toString()) }
            .setNeutralButton("چسباندن از کلیپ‌بورد") { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val pasted = clipboard.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString().orEmpty()
                importText(pasted)
            }
            .setNegativeButton("انصراف", null)
            .show()
    }

    private fun showSubscriptionImport() {
        val input = EditText(this).apply { hint = "https://example.com/subscription" }
        AlertDialog.Builder(this)
            .setTitle("دریافت اشتراک")
            .setMessage("نشانی اشتراک باید متعلق به منبعی باشد که به آن اعتماد دارید.")
            .setView(input)
            .setPositiveButton("دریافت") { _, _ -> fetchSubscription(input.text.toString().trim()) }
            .setNegativeButton("انصراف", null)
            .show()
    }

    private fun openConfigFile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        startActivityForResult(intent, REQUEST_CONFIG)
    }

    @Deprecated("Deprecated in Android SDK")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_PERMISSION) {
            if (resultCode == RESULT_OK) {
                val config = pendingVpnConfig
                if (!config.isNullOrBlank()) startVpnService(config)
            } else {
                toast("مجوز ایجاد تونل VPN داده نشد.")
                if (autoConnecting) tryNextAutoCandidate("مجوز VPN رد شد")
            }
            pendingVpnConfig = null
            return
        }
        if (requestCode == REQUEST_CONFIG && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            try {
                val text = contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }.orEmpty()
                importText(text)
            } catch (e: Exception) {
                toast("خواندن فایل ناموفق بود: ${e.message}")
            }
        }
    }

    private var pendingVpnConfig: String? = null

    private fun startAutoConnect() {
        if (autoConnecting) return
        autoConnecting = true
        autoCandidateIndex = 0
        autoCandidates = emptyList()
        statusView.text = "در حال آماده‌سازی اتصال هوشمند…"
        val custom = getSharedPreferences(PREFS, MODE_PRIVATE)
            .getString(KEY_AUTO_SOURCE, DEFAULT_AUTO_SOURCE) ?: DEFAULT_AUTO_SOURCE
        // Keep saved profiles, but always refresh from several independently maintained feeds.
        autoSourceList = buildList {
            if (custom != DEFAULT_AUTO_SOURCE) add(custom)
            add(DEFAULT_AUTO_SOURCE)
            add("https://cdn.jsdelivr.net/gh/morpheusadam/v2ray-config@main/subs/bundles/best.txt")
            add("https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt")
            add("https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt")
            add("https://raw.githubusercontent.com/3000S-HTTP/sNSub/main/output/best59.txt")
            add("https://raw.githubusercontent.com/chaishpish/free_server_v2ray/main/%40TFMTProto")
        }.distinct()
        autoSourceIndex = 0
        fetchNextAutoSource()
    }

    private fun fetchNextAutoSource() {
        if (!autoConnecting) return
        if (autoSourceIndex >= autoSourceList.size) {
            statusView.text = "دریافت منابع تمام شد؛ ${servers.size} کانفیگ یکتا برای بررسی پیدا شد."
            rankAndConnectAutomatically()
            return
        }
        val address = autoSourceList[autoSourceIndex++]
        statusView.text = "در حال دریافت منبع ${autoSourceIndex} از ${autoSourceList.size}…"
        fetchSubscription(address, true)
    }

    private fun rankAndConnectAutomatically() {
        val allCandidates = servers.distinctBy { it.raw }
        // Test a priority slice plus a spread across later feeds, so one stale
        // subscription cannot monopolize the entire connection attempt.
        val prioritySlice = allCandidates.take(350)
        val remaining = allCandidates.drop(350)
        val sampleStep = maxOf(1, remaining.size / 350)
        val diverseSlice = remaining.filterIndexed { index, _ -> index % sampleStep == 0 }.take(350)
        val snapshot = (prioritySlice + diverseSlice).distinctBy { it.raw }
        if (snapshot.isEmpty()) {
            autoConnecting = false
            statusView.text = "هیچ کانفیگ قابل پشتیبانی از منابع دریافت نشد."
            return
        }
        statusView.text = "در حال غربالگری ${snapshot.size} گزینه؛ آزمون UDP و TCP جداگانه انجام می‌شود…"
        io.execute {
            val udpProtocols = setOf("HYSTERIA", "HYSTERIA2", "HY2", "TUIC", "WIREGUARD", "WG")
            val tested = snapshot.map { server ->
                java.util.concurrent.CompletableFuture.supplyAsync {
                    if (server.protocol.uppercase(Locale.ROOT) in udpProtocols) {
                        // TCP probing cannot validate UDP transports; keep them for a real tunnel attempt.
                        server.latencyMs = -2L
                    } else {
                        val started = System.nanoTime()
                        server.latencyMs = try {
                            Socket().use { socket ->
                                socket.connect(java.net.InetSocketAddress(server.host, server.port), 1800)
                            }
                            (System.nanoTime() - started) / 1_000_000
                        } catch (_: Exception) { -1L }
                    }
                    server
                }
            }.mapNotNull { runCatching { it.get() }.getOrNull() }
                .filter { it.latencyMs >= 0 || it.latencyMs == -2L }
                .sortedWith(compareBy<ServerEntry> { if (it.latencyMs >= 0) 0 else 1 }
                    .thenBy { if (it.latencyMs >= 0) it.latencyMs else snapshot.indexOf(it) })
            runOnUiThread {
                if (!autoConnecting) return@runOnUiThread
                autoCandidates = tested
                autoCandidateIndex = 0
                if (tested.isEmpty()) {
                    autoConnecting = false
                    statusView.text = "هیچ سرور TCP قابل دسترسی و هیچ کانفیگ UDP برای آزمون پیدا نشد."
                } else {
                    saveServers()
                    connectNextRanked()
                }
            }
        }
    }

    private fun connectNextRanked() {
        if (!autoConnecting) return
        if (autoCandidateIndex >= autoCandidates.size) {
            autoConnecting = false
            statusView.text = "اتصال خودکار ناموفق بود؛ هیچ‌یک از سرورهای آزمایش‌شده تونل قابل استفاده نساختند."
            return
        }
        val server = autoCandidates[autoCandidateIndex++]
        statusView.text = "در حال امتحان گزینه ${autoCandidateIndex} از ${autoCandidates.size}: ${server.name} (${server.latencyMs} ms)"
        connectServer(server)
    }

    private fun tryNextAutoCandidate(reason: String) {
        if (!autoConnecting) return
        statusView.text = "این گزینه ناموفق بود؛ در حال امتحان گزینه بعدی…"
        handler.postDelayed({ if (autoConnecting) connectNextRanked() }, 700)
    }

    private fun showServerPicker() {
        if (servers.isEmpty()) { toast("ابتدا لینک یا فایل کانفیگ معتبر وارد کنید."); return }
        AlertDialog.Builder(this).setTitle("انتخاب سرور برای اتصال")
            .setItems(servers.map { "${it.name} — ${it.protocol} — ${it.host}:${it.port}" }.toTypedArray()) { _, which -> connectServer(servers[which]) }
            .setNegativeButton("انصراف", null).show()
    }

    private fun connectServer(server: ServerEntry) {
        try {
            val config = SingBoxConfigBuilder.build(server.raw)
            val permission = VpnService.prepare(this)
            if (permission != null) { pendingVpnConfig = config; startActivityForResult(permission, REQUEST_VPN_PERMISSION) }
            else startVpnService(config)
        } catch (e: Exception) {
            statusView.text = "خطای پیکربندی: ${e.message}"
            toast("این کانفیگ قابل اجرا نیست: ${e.message}")
            if (autoConnecting) tryNextAutoCandidate(e.message ?: "کانفیگ نامعتبر")
        }
    }

    private fun startVpnService(config: String) {
        val intent = Intent(this, SingBoxVpnService::class.java).putExtra(SingBoxVpnService.EXTRA_CONFIG, config)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent) else startService(intent)
            statusView.text = "وضعیت: درخواست راه‌اندازی تونل به sing-box ارسال شد."
        } catch (e: Exception) {
            statusView.text = "خطا در شروع سرویس VPN: ${e.message}"
            toast("شروع سرویس VPN ناموفق بود: ${e.message}")
        }
    }

    private fun stopVpn() {
        val intent = Intent(this, SingBoxVpnService::class.java).setAction(SingBoxVpnService.ACTION_STOP)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent) else startService(intent)
            statusView.text = "وضعیت: درخواست قطع اتصال ارسال شد."
        } catch (_: Exception) { statusView.text = "وضعیت: اتصال VPN فعال نیست یا سرویس در دسترس نیست." }
    }

    private fun fetchSubscription(address: String, forAutoConnect: Boolean = false) {
        if (!address.startsWith("https://")) {
            toast("برای امنیت، فقط نشانی HTTPS پذیرفته می‌شود.")
            return
        }
        statusView.text = "وضعیت: دریافت اشتراک…"
        io.execute {
            try {
                val connection = URL(address).openConnection() as HttpURLConnection
                connection.connectTimeout = 10000
                connection.readTimeout = 15000
                connection.instanceFollowRedirects = true
                connection.setRequestProperty("User-Agent", "SmartVPN-Android/0.2")
                val body = connection.inputStream.bufferedReader().use { it.readText() }
                connection.disconnect()
                val parseBody = if (forAutoConnect && body.contains("://")) {
                    body.lineSequence().take(900).joinToString("\n")
                } else body
                val count = addParsedContent(parseBody)
                runOnUiThread {
                    renderServers()
                    saveServers()
                    if (forAutoConnect) {
                        fetchNextAutoSource()
                    } else statusView.text = "دریافت تمام شد؛ $count کانفیگ جدید شناسایی شد"
                }
            } catch (e: Exception) {
                runOnUiThread {
                    if (forAutoConnect) fetchNextAutoSource()
                    else statusView.text = "خطا در دریافت اشتراک: ${e.localizedMessage}"
                }
            }
        }
    }

    private fun importText(text: String) {
        val count = addParsedContent(text)
        if (count > 0) {
            saveServers()
            renderServers()
            toast("$count کانفیگ جدید اضافه شد.")
        } else {
            toast("کانفیگ قابل شناسایی پیدا نشد. قالب لینک یا متن اشتراک را بررسی کنید.")
        }
    }

    private fun addParsedContent(input: String): Int {
        var content = input.trim().removePrefix("\uFEFF")
        if (content.isBlank()) return 0
        if (!content.contains("://")) {
            val decoded = runCatching {
                String(Base64.decode(content.replace("\\s".toRegex(), ""), Base64.DEFAULT), StandardCharsets.UTF_8)
            }.getOrNull()
            if (!decoded.isNullOrBlank() && decoded.contains("://")) content = decoded
        }
        if (content.startsWith("{")) {
            val completeProfile = parseConfig(content)
            if (completeProfile != null && servers.none { it.raw == completeProfile.raw }) {
                servers.add(completeProfile)
                return 1
            }
            return 0
        }
        var added = 0
        content.lineSequence().map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .take(2500)
            .forEach { line ->
                if (servers.size >= 5000) return@forEach
                val entry = parseConfig(line) ?: return@forEach
                if (servers.none { it.raw == entry.raw }) {
                    servers.add(entry)
                    added++
                }
            }
        return added
    }

    private fun parseConfig(rawLine: String): ServerEntry? {
        return try {
            val original = rawLine.trim()
            // Strip provider annotations and display fragments before URI parsing.
            // Some public feeds append unescaped labels/emoji after '#', which
            // makes java.net.URI reject otherwise valid server credentials.
            val line = if (original.startsWith("{")) original
                else original.substringBefore(" | ").substringBefore("#").trim()
            if (line.startsWith("{")) {
                val config = JSONObject(line)
                val outbounds = config.optJSONArray("outbounds") ?: return null
                for (i in 0 until outbounds.length()) {
                    val outbound = outbounds.optJSONObject(i) ?: continue
                    val protocol = outbound.optString("type")
                    if (protocol in setOf("direct", "block", "dns", "selector", "urltest")) continue
                    val host = outbound.optString("server")
                    val port = outbound.optInt("server_port")
                    if (host.isNotBlank() && port in 1..65535) {
                        return ServerEntry(UUID.randomUUID().toString(), outbound.optString("tag").ifBlank { host },
                            protocol.uppercase(Locale.ROOT), host, port, line)
                    }
                }
                return null
            }
            if (line.startsWith("vmess://", true)) {
                val encoded = line.substringAfter("://").substringBefore("#")
                val jsonText = String(Base64.decode(encoded, Base64.DEFAULT), StandardCharsets.UTF_8)
                val json = JSONObject(jsonText)
                val host = json.optString("add").takeIf { it.isNotBlank() } ?: return null
                val port = json.optString("port").toIntOrNull() ?: return null
                val name = json.optString("ps").ifBlank { host }
                return ServerEntry(UUID.randomUUID().toString(), name, "VMess", host, port, line)
            }
            var normalized = line
            var scheme = line.substringBefore("://", "").lowercase(Locale.ROOT)
            if (scheme == "hysteria2") scheme = "hy2"
            if (scheme == "wg") scheme = "wireguard"
            if (scheme == "ss") {
                val payload = line.substringAfter("://").substringBefore("#")
                val decoded = runCatching { String(Base64.decode(payload, Base64.DEFAULT), StandardCharsets.UTF_8) }.getOrNull()
                if (decoded != null && decoded.contains("@")) normalized = "ss://$decoded"
            }
            val uri = URI(normalized)
            val host = uri.host?.takeIf { it.isNotBlank() } ?: return null
            val port = uri.port.takeIf { it in 1..65535 } ?: return null
            val supported = mapOf(
                "vless" to "VLESS", "vmess" to "VMess", "trojan" to "Trojan",
                "ss" to "Shadowsocks", "hy2" to "Hysteria2", "tuic" to "TUIC",
                "wireguard" to "WireGuard", "wg" to "WireGuard"
            )
            val protocol = supported[scheme] ?: return null
            val name = uri.fragment?.takeIf { it.isNotBlank() }?.let {
                runCatching { java.net.URLDecoder.decode(it, "UTF-8") }.getOrDefault(it)
            } ?: host
            ServerEntry(UUID.randomUUID().toString(), name, protocol, host, port, line)
        } catch (_: Exception) {
            null
        }
    }

    private fun testAllServers() {
        if (servers.isEmpty()) {
            toast("ابتدا یک کانفیگ وارد کنید.")
            return
        }
        statusView.text = "وضعیت: در حال آزمایش دسترس‌پذیری سرورها…"
        val snapshot = servers.toList()
        io.execute {
            snapshot.forEach { server ->
                val start = System.nanoTime()
                server.latencyMs = try {
                    Socket().use { socket ->
                        socket.connect(java.net.InetSocketAddress(server.host, server.port), 3500)
                    }
                    (System.nanoTime() - start) / 1_000_000
                } catch (_: Exception) { -1 }
            }
            runOnUiThread {
                servers.sortWith(compareBy<ServerEntry> { if (it.latencyMs < 0) Long.MAX_VALUE else it.latencyMs })
                statusView.text = "وضعیت: آزمایش TCP تمام شد؛ این نتیجه تضمین اتصال VPN نیست."
                renderServers()
                saveServers()
            }
        }
    }

    private fun renderServers() {
        listView.removeAllViews()
        if (servers.isEmpty()) {
            listView.addView(TextView(this).apply {
                text = "هنوز سروری اضافه نشده است."
                setTextColor(Color.LTGRAY)
                textSize = 14f
            })
            return
        }
        servers.forEachIndexed { index, server ->
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(12, 10, 12, 10)
                setBackgroundColor(Color.rgb(24, 39, 58))
            }
            val latency = if (server.latencyMs >= 0) "${server.latencyMs} ms (TCP)" else "آزمایش نشده / ناموفق"
            card.addView(TextView(this).apply {
                text = "${index + 1}. ${server.name}\n${server.protocol}  •  ${server.host}:${server.port}\nوضعیت: $latency"
                setTextColor(Color.WHITE)
                textSize = 14f
            })
            card.addView(Button(this).apply {
                text = "اتصال به این سرور"
                setOnClickListener { connectServer(server) }
            })
            card.addView(Button(this).apply {
                text = "حذف سرور"
                setOnClickListener {
                    servers.removeAll { it.id == server.id }
                    saveServers()
                    renderServers()
                }
            })
            listView.addView(card, matchWidth())
        }
    }

    private fun loadServers() {
        val data = getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_SERVERS, "[]") ?: "[]"
        runCatching {
            val array = JSONArray(data)
            for (i in 0 until array.length()) {
                val item = array.getJSONObject(i)
                servers.add(ServerEntry(
                    item.getString("id"), item.getString("name"), item.getString("protocol"),
                    item.getString("host"), item.getInt("port"), item.getString("raw"),
                    item.optLong("latency", -1)
                ))
            }
        }
    }

    private fun saveServers() {
        val array = JSONArray()
        servers.forEach { server ->
            array.put(JSONObject().apply {
                put("id", server.id); put("name", server.name); put("protocol", server.protocol)
                put("host", server.host); put("port", server.port); put("raw", server.raw)
                put("latency", server.latencyMs)
            })
        }
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString(KEY_SERVERS, array.toString()).apply()
    }

    private fun formatRate(bytes: Long): String {
        val kb = bytes / 1024.0
        return if (kb >= 1024) String.format(Locale.US, "%.2f MB/s", kb / 1024)
        else String.format(Locale.US, "%.1f KB/s", kb)
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()

    override fun onDestroy() {
        handler.removeCallbacks(trafficRefresh)
        io.shutdownNow()
        super.onDestroy()
    }

    companion object {
        private const val REQUEST_CONFIG = 41
        private const val REQUEST_VPN_PERMISSION = 42
        private const val PREFS = "smartvpn_storage"
        private const val KEY_SERVERS = "servers"
        private const val KEY_AUTO_SOURCE = "auto_source"
        private const val DEFAULT_AUTO_SOURCE = "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt"
    }
}
