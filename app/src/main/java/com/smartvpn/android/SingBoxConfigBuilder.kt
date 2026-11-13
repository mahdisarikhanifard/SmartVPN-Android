package com.smartvpn.android

import android.net.Uri
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Converts common share links to a sing-box config. Unsupported or incomplete
 * links fail closed: they are never passed to the native engine as fake profiles.
 */
object SingBoxConfigBuilder {
    fun build(raw: String): String {
        val line = raw.trim()
        val outbound = when {
            line.startsWith("vmess://", true) -> vmess(line)
            line.startsWith("vless://", true) -> uriOutbound(line, "vless")
            line.startsWith("trojan://", true) -> uriOutbound(line, "trojan")
            line.startsWith("ss://", true) -> shadowsocks(line)
            line.startsWith("hysteria2://", true) || line.startsWith("hy2://", true) -> uriOutbound(line, "hysteria2")
            line.startsWith("tuic://", true) -> uriOutbound(line, "tuic")
            line.startsWith("wireguard://", true) || line.startsWith("wg://", true) -> wireguard(line)
            line.startsWith("{") -> {
                val parsed = JSONObject(line)
                if (parsed.has("outbounds")) return line
                throw IllegalArgumentException("JSON کانفیگ باید ساختار کامل sing-box داشته باشد.")
            }
            else -> throw IllegalArgumentException("پروتکل این کانفیگ پشتیبانی نمی‌شود.")
        }
        val outbounds = JSONArray().put(outbound).put(JSONObject().put("type", "direct").put("tag", "direct"))
        return JSONObject()
            .put("log", JSONObject().put("level", "info").put("timestamp", true))
            .put("dns", JSONObject().put("servers", JSONArray().put(JSONObject().put("tag", "remote-dns").put("address", "https://1.1.1.1/dns-query").put("detour", "proxy"))).put("final", "remote-dns").put("strategy", "prefer_ipv4"))
            .put("inbounds", JSONArray().put(JSONObject()
                .put("type", "tun").put("tag", "tun-in")
                .put("interface_name", "tun0")
                .put("inet4_address", JSONArray().put("172.19.0.1/30"))
                .put("inet6_address", JSONArray().put("fdfe:dcba:9876::1/126"))
                .put("mtu", 9000).put("auto_route", true).put("strict_route", true)
                .put("stack", "system")))
            .put("outbounds", outbounds)
            .put("route", JSONObject().put("auto_detect_interface", true).put("final", "proxy"))
            .toString(2)
    }

    private fun vmess(link: String): JSONObject {
        val encoded = link.substringAfter("://").substringBefore("#")
        val text = String(Base64.decode(pad(encoded), Base64.DEFAULT), StandardCharsets.UTF_8)
        val data = JSONObject(text)
        val server = data.optString("add")
        val port = data.optInt("port")
        val uuid = data.optString("id")
        require(server.isNotBlank() && port in 1..65535 && uuid.isNotBlank()) { "اطلاعات VMess ناقص است." }
        val tls = data.optString("tls").equals("tls", true)
        val out = JSONObject().put("type", "vmess").put("tag", "proxy")
            .put("server", server).put("server_port", port).put("uuid", uuid)
            .put("security", data.optString("scy").ifBlank { "auto" })
            .put("alter_id", data.optInt("aid", 0))
        if (tls) out.put("tls", JSONObject().put("enabled", true)
            .put("server_name", data.optString("sni").ifBlank { data.optString("host").ifBlank { server } })
            .put("insecure", false))
        when (data.optString("net").lowercase()) {
            "ws" -> out.put("transport", JSONObject().put("type", "ws")
                .put("path", data.optString("path").ifBlank { "/" })
                .put("headers", JSONObject().put("Host", data.optString("host"))))
            "grpc" -> out.put("transport", JSONObject().put("type", "grpc").put("service_name", data.optString("path")))
        }
        return out
    }

    private fun uriOutbound(link: String, type: String): JSONObject {
        val uri = URI(link)
        val parsed = Uri.parse(link)
        val host = uri.host ?: throw IllegalArgumentException("نشانی سرور معتبر نیست.")
        val port = uri.port
        require(port in 1..65535) { "پورت سرور معتبر نیست." }
        val userInfo = uri.rawUserInfo?.let { decode(it) }.orEmpty()
        val query = parsed
        val out = JSONObject().put("type", type).put("tag", "proxy").put("server", host).put("server_port", port)
        when (type) {
            "vless" -> {
                require(userInfo.isNotBlank()) { "شناسه UUID در لینک VLESS وجود ندارد." }
                out.put("uuid", userInfo)
                query.getQueryParameter("flow")?.takeIf { it.isNotBlank() }?.let { out.put("flow", it) }
                addTls(out, query, host)
                addTransport(out, query)
            }
            "trojan" -> {
                require(userInfo.isNotBlank()) { "رمز عبور در لینک Trojan وجود ندارد." }
                out.put("password", userInfo)
                addTls(out, query, host)
                addTransport(out, query)
            }
            "hysteria2" -> {
                require(userInfo.isNotBlank()) { "رمز عبور در لینک Hysteria2 وجود ندارد." }
                out.put("password", userInfo)
                addTls(out, query, host)
                query.getQueryParameter("obfs")?.let { obfs ->
                    out.put("obfs", JSONObject().put("type", obfs).put("password", query.getQueryParameter("obfs-password").orEmpty()))
                }
                query.getQueryParameter("up")?.toIntOrNull()?.let { out.put("up_mbps", it) }
                query.getQueryParameter("down")?.toIntOrNull()?.let { out.put("down_mbps", it) }
            }
            "tuic" -> {
                val parts = userInfo.split(":", limit = 2)
                require(parts.size == 2 && parts.all { it.isNotBlank() }) { "UUID یا رمز عبور TUIC ناقص است." }
                out.put("uuid", parts[0]).put("password", parts[1])
                    .put("congestion_control", query.getQueryParameter("congestion_control") ?: "bbr")
                    .put("udp_relay_mode", query.getQueryParameter("udp_relay_mode") ?: "native")
                    .put("zero_rtt_handshake", false)
                addTls(out, query, host)
            }
        }
        return out
    }

    private fun shadowsocks(link: String): JSONObject {
        val uri = URI(link)
        val host = uri.host ?: throw IllegalArgumentException("نشانی Shadowsocks معتبر نیست.")
        require(uri.port in 1..65535) { "پورت Shadowsocks معتبر نیست." }
        var credentials = uri.rawUserInfo?.let { decode(it) }.orEmpty()
        // SIP002 links commonly put base64(method:password) in URI user-info.
        // Decode it even when URI has already parsed a non-empty rawUserInfo.
        if (credentials.isNotBlank() && !credentials.contains(':')) {
            credentials = runCatching {
                String(Base64.decode(pad(credentials), Base64.DEFAULT), StandardCharsets.UTF_8)
            }.recoverCatching {
                String(Base64.decode(pad(credentials), Base64.URL_SAFE or Base64.NO_WRAP), StandardCharsets.UTF_8)
            }.getOrDefault(credentials)
        }
        if (credentials.isBlank()) {
            val authority = link.substringAfter("://").substringBefore("@").substringBefore("#")
            credentials = String(Base64.decode(pad(authority), Base64.DEFAULT), StandardCharsets.UTF_8)
        }
        val split = credentials.indexOf(':')
        require(split > 0 && split < credentials.lastIndex) { "روش رمزنگاری یا رمز عبور Shadowsocks ناقص است." }
        return JSONObject().put("type", "shadowsocks").put("tag", "proxy")
            .put("server", host).put("server_port", uri.port)
            .put("method", credentials.substring(0, split))
            .put("password", credentials.substring(split + 1))
    }

    private fun wireguard(link: String): JSONObject {
        val q = Uri.parse(link)
        val host = q.getQueryParameter("server") ?: URI(link).host
            ?: throw IllegalArgumentException("برای WireGuard باید server مشخص شود.")
        val port = q.getQueryParameter("server_port")?.toIntOrNull() ?: URI(link).port
        val privateKey = q.getQueryParameter("private_key").orEmpty()
        val peerKey = q.getQueryParameter("peer_public_key").orEmpty()
        val address = q.getQueryParameter("address").orEmpty()
        require(port in 1..65535 && privateKey.isNotBlank() && peerKey.isNotBlank() && address.isNotBlank()) {
            "WireGuard: private_key، peer_public_key، address و server_port لازم است."
        }
        return JSONObject().put("type", "wireguard").put("tag", "proxy")
            .put("server", host).put("server_port", port)
            .put("private_key", privateKey)
            .put("peer_public_key", peerKey)
            .put("local_address", JSONArray().put(address))
            .put("reserved", JSONArray())
    }

    private fun addTls(out: JSONObject, q: Uri, host: String) {
        val security = q.getQueryParameter("security")
        val sni = q.getQueryParameter("sni") ?: q.getQueryParameter("peer") ?: host
        val tls = JSONObject().put("enabled", security == null || security == "tls" || security == "reality")
            .put("server_name", sni).put("insecure", false)
        q.getQueryParameter("alpn")?.let { tls.put("alpn", JSONArray(it.split(',').filter(String::isNotBlank))) }
        if (security == "reality") {
            val reality = JSONObject().put("enabled", true)
            q.getQueryParameter("pbk")?.let { reality.put("public_key", it) }
            q.getQueryParameter("sid")?.let { reality.put("short_id", it) }
            tls.put("reality", reality)
        }
        out.put("tls", tls)
    }

    private fun addTransport(out: JSONObject, q: Uri) {
        when (q.getQueryParameter("type")?.lowercase()) {
            "ws" -> out.put("transport", JSONObject().put("type", "ws")
                .put("path", q.getQueryParameter("path") ?: "/")
                .put("headers", JSONObject().put("Host", q.getQueryParameter("host") ?: "")))
            "grpc" -> out.put("transport", JSONObject().put("type", "grpc")
                .put("service_name", q.getQueryParameter("serviceName") ?: q.getQueryParameter("service_name") ?: ""))
            "http", "h2" -> out.put("transport", JSONObject().put("type", "http")
                .put("path", q.getQueryParameter("path") ?: "/"))
        }
    }

    private fun decode(value: String): String = URLDecoder.decode(value, "UTF-8")
    private fun pad(value: String): String = value + "=".repeat((4 - value.length % 4) % 4)
}
