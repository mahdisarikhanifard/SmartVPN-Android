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
                "connected" -> statusView.text = "وضعیت: VPN متصل است"
                "disconnected" -> statusView.text = "وضعیت: اتصال VPN قطع است"
                "error" -> statusView.text = "خطای اتصال VPN: ${intent.getStringExtra("error") ?: "نامشخص"}"
            }
        }
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(SingBoxVpnService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(vpnStatusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        else @Suppress("DEPRECATION") registerReceiver(vpnStatusReceiver, filter)
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
            setPadding(24, 28, 24, 24)
            setBackgroundColor(Color.rgb(10, 21, 38))
        }
        fun label(value: String, size: Float, color: Int = Color.WHITE, bold: Boolean = false) =
            TextView(this).apply {
                text = value
                textSize = size
                setTextColor(color)
                if (bold) setTypeface(null, Typeface.BOLD)
                setPadding(0, 9, 0, 9)
            }

        root.addView(label("SmartVPN", 28f, Color.WHITE, true))
        root.addView(label("مدیریت سرورها و کانفیگ‌ها", 15f, Color.LTGRAY))
        statusView = label("وضعیت: موتور تونل هنوز به برنامه متصل نشده است", 15f, Color.rgb(255, 190, 80), true)
        root.addView(statusView)
        val connect = Button(this).apply {
            text = "انتخاب سرور و اتصال VPN"
            setOnClickListener { showServerPicker() }
        }
        root.addView(connect, matchWidth())
        addButton("قطع اتصال VPN") { stopVpn() }
        root.addView(label("مدیریت کانفیگ‌ها", 19f, Color.WHITE, true))
        addButton("افزودن لینک یا متن کانفیگ") { showTextImport() }
        addButton("افزودن اشتراک از نشانی اینترنتی") { showSubscriptionImport() }
        addButton("وارد کردن فایل یا QR متنی") { openConfigFile() }
        addButton("آزمایش دسترس‌پذیری همه سرورها") { testAllServers() }
        trafficView = label("در حال اندازه‌گیری ترافیک…", 13f, Color.rgb(110, 220, 180))
        root.addView(trafficView)
        root.addView(label("فهرست سرورها", 19f, Color.WHITE, true))
        listView = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(listView)
        root.addView(label("توجه: آزمایش فعلی فقط اتصال TCP به میزبان و پورت را می‌سنجد؛ تست واقعی تونل، پینگ داخل VPN و سرعت اختصاصی پس از ادغام موتور انجام می‌شود. کانفیگ عمومی ناشناس قابل اعتماد فرض نمی‌شود.", 12f, Color.LTGRAY))
        setContentView(ScrollView(this).apply { addView(root) })
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
            } else toast("مجوز ایجاد تونل VPN داده نشد.")
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

    private fun fetchSubscription(address: String) {
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
                val count = addParsedContent(body)
                runOnUiThread {
                    statusView.text = "وضعیت: دریافت تمام شد؛ $count کانفیگ جدید شناسایی شد"
                    renderServers()
                    saveServers()
                }
            } catch (e: Exception) {
                runOnUiThread { statusView.text = "خطا در دریافت اشتراک: ${e.localizedMessage}" }
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
        var added = 0
        content.lineSequence().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.forEach { line ->
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
            val line = rawLine.trim()
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
    }
}
