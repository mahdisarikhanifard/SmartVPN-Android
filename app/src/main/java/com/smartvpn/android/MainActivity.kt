package com.smartvpn.android

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.net.TrafficStats
import android.os.Handler
import android.os.Looper
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.graphics.Typeface
import android.graphics.Color
import java.util.Locale

class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private var previousRx = TrafficStats.getTotalRxBytes()
    private var previousTx = TrafficStats.getTotalTxBytes()
    private lateinit var trafficView: TextView
    private lateinit var configView: TextView
    private val refresh = object : Runnable {
        override fun run() {
            val rx = TrafficStats.getTotalRxBytes()
            val tx = TrafficStats.getTotalTxBytes()
            val down = if (rx >= 0 && previousRx >= 0) (rx - previousRx).coerceAtLeast(0) else 0
            val up = if (tx >= 0 && previousTx >= 0) (tx - previousTx).coerceAtLeast(0) else 0
            trafficView.text = "دریافت: ${formatRate(down)}\nارسال: ${formatRate(up)}"
            previousRx = rx; previousTx = tx
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 36, 28, 24)
            setBackgroundColor(Color.rgb(12, 24, 42))
        }
        fun text(value: String, size: Float, color: Int = Color.WHITE, bold: Boolean = false) =
            TextView(this).apply {
                text = value; textSize = size; setTextColor(color)
                if (bold) setTypeface(null, Typeface.BOLD)
                setPadding(0, 12, 0, 12)
            }
        root.addView(text("SmartVPN", 28f, Color.WHITE, true))
        root.addView(text("مدیریت اتصال چندمسیره — نسخه آزمایشی ۰٫۱", 15f, Color.LTGRAY))
        root.addView(text("وضعیت: موتور تونل هنوز متصل نیست", 18f, Color.rgb(255, 196, 87), true))
        root.addView(text("سرعت شبکه دستگاه", 18f, Color.WHITE, true))
        trafficView = text("در حال اندازه‌گیری…", 17f, Color.rgb(110, 220, 180))
        root.addView(trafficView)
        root.addView(text("کانفیگ‌های واردشده", 18f, Color.WHITE, true))
        configView = text("هنوز کانفیگی وارد نشده است", 14f, Color.LTGRAY)
        root.addView(configView)
        val importButton = Button(this).apply {
            text = "افزودن فایل کانفیگ"
            setOnClickListener {
                val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "*/*"
                }
                startActivityForResult(intent, REQUEST_CONFIG)
            }
        }
        root.addView(importButton, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        root.addView(text("این نسخه فقط رابط اولیه، شناسایی قالب لینک‌ها و سنجش ترافیک کلی دستگاه را دارد. اتصال VPN، اسکن منابع عمومی و تست واقعی سرورها هنوز پیاده‌سازی نشده‌اند.", 13f, Color.LTGRAY))
        setContentView(ScrollView(this).apply { addView(root) })
        handler.post(refresh)
    }

    @Deprecated("Deprecated in Android SDK")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_CONFIG && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            try {
                val content = contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }.orEmpty()
                val prefixes = listOf("vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://", "tuic://", "wg://")
                val lines = content.lines().map { it.trim() }.filter { line -> prefixes.any { line.startsWith(it, true) } }
                configView.text = "تعداد لینک‌های شناسایی‌شده: ${lines.size}\n" +
                    lines.take(5).joinToString("\n") { it.take(72) } +
                    if (lines.size > 5) "\n…" else ""
            } catch (e: Exception) {
                configView.text = "خواندن فایل ناموفق بود: ${e.localizedMessage}"
            }
        }
    }

    private fun formatRate(bytes: Long): String {
        val kb = bytes / 1024.0
        return if (kb >= 1024) String.format(Locale.US, "%.2f MB/s", kb / 1024)
        else String.format(Locale.US, "%.1f KB/s", kb)
    }

    override fun onDestroy() {
        handler.removeCallbacks(refresh)
        super.onDestroy()
    }

    companion object { private const val REQUEST_CONFIG = 41 }
}
