package com.smartvpn.android

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Persistent diagnostic journal shared by the activity and VPN service.
 * Only authored status messages are stored; configuration payloads are never logged.
 */
object EventLog {
    private const val PREFS = "smartvpn_storage"
    private const val KEY_EVENTS = "diagnostic_events"
    private const val MAX_EVENTS = 800

    @Synchronized
    fun append(context: Context, message: String) {
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val current = prefs.getString(KEY_EVENTS, "").orEmpty()
        val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        val safe = redact(message).replace("\r", " ").replace("\n", " ").take(500)
        val lines = (current.lineSequence().filter { it.isNotBlank() } + sequenceOf("[$stamp] $safe"))
            .toList().takeLast(MAX_EVENTS)
        prefs.edit().putString(KEY_EVENTS, lines.joinToString("\n")).apply()
    }

    fun read(context: Context): String {
        val value = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_EVENTS, "").orEmpty()
        return if (value.isBlank()) "هنوز رویدادی ثبت نشده است." else value
    }

    private fun redact(input: String): String {
        var value = input
        value = value.replace(Regex("(?i)(vless|vmess|trojan|ss|hysteria2|hy2|tuic|wireguard)://\\S+"), "$1://[محرمانه]")
        value = value.replace(Regex("(?i)(password|passwd|token|uuid|private[_-]?key)\\s*[:=]\\s*[^,\\s]+"), "$1=[محرمانه]")
        return value
    }
}
