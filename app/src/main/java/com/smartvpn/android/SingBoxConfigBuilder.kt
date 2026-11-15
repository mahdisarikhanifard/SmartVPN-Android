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
        if (line.contains("[Interface]", ignoreCase = true) &&
            line.contains("[Peer]", ignoreCase = true)) {
            return buildWireGuardIni(line)
        }
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
                if (parsed.has("outbounds")) return addLocalProbeInbound(parsed).toString(2)
                throw IllegalArgumentException("JSON کانفیگ باید ساختار کامل sing-box داشته باشد.")
            }
            else -> throw IllegalArgumentException("پروتکل این کانفیگ پشتیبانی نمی‌شود.")
        }
        val outbounds = JSONArray().put(outbound).put(JSONObject().put("type", "direct").put("tag", "direct"))
        return JSONObject()
            .put("log", JSONObject().put("level", "debug").put("timestamp", true))
            .put("dns", JSONObject().put("servers", JSONArray().put(JSONObject().put("type", "https").put("tag", "remote-dns").put("server", "1.1.1.1").put("path", "/dns-query").put("detour", "proxy"))).put("final", "remote-dns").put("strategy", "prefer_ipv4"))
            .put("inbounds", JSONArray().put(JSONObject()
                .put("type", "tun").put("tag", "tun-in")
                .put("address", JSONArray().put("172.19.0.1/30").put("fdfe:dcba:9876::1/126"))
                .put("mtu", 1500).put("auto_route", true)
                .put("stack", "system"))
                .put(JSONObject().put("type", "mixed").put("tag", "smartvpn-local-probe").put("listen", "127.0.0.1").put("listen_port", 20808)))
            .put("outbounds", outbounds)
            .put("route", JSONObject().put("auto_detect_interface", true).put("final", "proxy"))
            .toString(2)
    }

    /**
     * Build one live sing-box profile containing a URLTest group. sing-box tests
     * each outbound through a real HTTPS request and selects the lowest measured
     * proxy-path delay; raw TCP port latency is only used to shortlist candidates.
     */
    fun buildAuto(rawCandidates: List<String>): String {
        val nodes = JSONArray()
        val tags = JSONArray()
        rawCandidates.distinct().forEachIndexed { index, raw ->
            val line = raw.trim()
            // Full JSON profiles are tested through the legacy single-profile
            // fallback; only share links can safely be merged into this group.
            val outbound = runCatching { outboundFromLink(line) }.getOrNull()
                ?: return@forEachIndexed
            val tag = "smartvpn-node-$index"
            outbound.put("tag", tag)
            nodes.put(outbound)
            tags.put(tag)
        }
        require(nodes.length() > 0) { "هیچ کانفیگ لینک‌محور قابل ساختی برای آزمون خودکار وجود ندارد." }
        nodes.put(JSONObject()
            .put("type", "urltest")
            .put("tag", "auto")
            .put("outbounds", tags)
            .put("url", "https://cp.cloudflare.com/generate_204")
            .put("interval", "30s")
            .put("tolerance", 100)
            .put("idle_timeout", "5m")
            .put("interrupt_exist_connections", false))
        nodes.put(JSONObject().put("type", "direct").put("tag", "direct"))
        return JSONObject()
            .put("log", JSONObject().put("level", "debug").put("timestamp", true))
            .put("dns", JSONObject()
                .put("servers", JSONArray().put(JSONObject()
                    .put("type", "https").put("tag", "remote-dns")
                    .put("server", "1.1.1.1").put("path", "/dns-query")))
                .put("final", "remote-dns").put("strategy", "prefer_ipv4"))
            .put("inbounds", JSONArray()
                .put(JSONObject()
                    .put("type", "tun").put("tag", "tun-in")
                    .put("address", JSONArray().put("172.19.0.1/30").put("fdfe:dcba:9876::1/126"))
                    .put("mtu", 1500).put("auto_route", true).put("stack", "system"))
                .put(JSONObject().put("type", "mixed").put("tag", "smartvpn-local-probe")
                    .put("listen", "127.0.0.1").put("listen_port", 20808)))
            .put("outbounds", nodes)
            .put("route", JSONObject().put("auto_detect_interface", true).put("final", "auto"))
            .toString(2)
    }

    private fun outboundFromLink(line: String): JSONObject = when {
        line.startsWith("vmess://", true) -> vmess(line)
        line.startsWith("vless://", true) -> uriOutbound(line, "vless")
        line.startsWith("trojan://", true) -> uriOutbound(line, "trojan")
        line.startsWith("ss://", true) -> shadowsocks(line)
        line.startsWith("hysteria2://", true) || line.startsWith("hy2://", true) -> uriOutbound(line, "hysteria2")
        line.startsWith("tuic://", true) -> uriOutbound(line, "tuic")
        line.startsWith("wireguard://", true) || line.startsWith("wg://", true) -> wireguard(line)
        else -> throw IllegalArgumentException("قالب کانفیگ برای گروه خودکار پشتیبانی نمی‌شود.")
    }

    private fun addLocalProbeInbound(config: JSONObject): JSONObject {
        val inbounds = config.optJSONArray("inbounds") ?: JSONArray().also { config.put("inbounds", it) }
        val exists = (0 until inbounds.length()).any { index ->
            inbounds.optJSONObject(index)?.optString("tag") == "smartvpn-local-probe"
        }
        if (!exists) {
            inbounds.put(JSONObject().put("type", "mixed").put("tag", "smartvpn-local-probe")
                .put("listen", "127.0.0.1").put("listen_port", 20808))
        }
        return config
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

    /**
     * Import a standard WireGuard .conf/.txt profile (for example Proton VPN).
     * The private key is only read locally and placed into the in-memory
     * sing-box configuration; it is never logged or transmitted by this code.
     *
     * sing-box 1.14.x uses WireGuard endpoints rather than the removed
     * WireGuard outbound type.
     */
    private fun buildWireGuardIni(text: String): String {
        val sections = linkedMapOf<String, MutableMap<String, String>>()
        var current = ""
        text.lineSequence().forEach { source ->
            val line = source.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) return@forEach
            if (line.startsWith("[") && line.endsWith("]")) {
                current = line.substring(1, line.length - 1).trim().lowercase()
                sections.getOrPut(current) { linkedMapOf() }
                return@forEach
            }
            val equals = line.indexOf('=')
            if (equals > 0 && current.isNotBlank()) {
                val key = line.substring(0, equals).trim().lowercase()
                val value = line.substring(equals + 1).substringBefore("#").trim()
                sections.getOrPut(current) { linkedMapOf() }[key] = value
            }
        }

        val iface = sections["interface"] ?: throw IllegalArgumentException("بخش [Interface] در فایل WireGuard پیدا نشد.")
        val peer = sections["peer"] ?: throw IllegalArgumentException("بخش [Peer] در فایل WireGuard پیدا نشد.")
        val privateKey = iface["privatekey"].orEmpty()
        val localAddresses = iface["address"].orEmpty().split(',').map { it.trim() }.filter { it.isNotBlank() }
        val endpoint = peer["endpoint"].orEmpty()
        val publicKey = peer["publickey"].orEmpty()
        val allowedIps = peer["allowedips"].orEmpty().split(',').map { it.trim() }.filter { it.isNotBlank() }
        require(privateKey.isNotBlank()) { "کلید خصوصی در بخش [Interface] وجود ندارد." }
        require(localAddresses.isNotEmpty()) { "آدرس داخلی Address در فایل WireGuard وجود ندارد." }
        require(publicKey.isNotBlank()) { "کلید عمومی Peer در فایل WireGuard وجود ندارد." }
        require(allowedIps.isNotEmpty()) { "AllowedIPs در بخش [Peer] وجود ندارد." }
        require(endpoint.isNotBlank()) { "Endpoint در بخش [Peer] وجود ندارد." }

        val server: String
        val port: Int
        if (endpoint.startsWith("[")) {
            val close = endpoint.indexOf(']')
            require(close > 1 && close + 2 < endpoint.length && endpoint[close + 1] == ':') {
                "قالب IPv6 در Endpoint معتبر نیست."
            }
            server = endpoint.substring(1, close)
            port = endpoint.substring(close + 2).toIntOrNull() ?: 0
        } else {
            val split = endpoint.lastIndexOf(':')
            require(split > 0) { "Endpoint باید به شکل host:port باشد." }
            server = endpoint.substring(0, split)
            port = endpoint.substring(split + 1).toIntOrNull() ?: 0
        }
        require(server.isNotBlank() && port in 1..65535) { "نشانی یا پورت Endpoint معتبر نیست." }

        val peerConfig = JSONObject()
            .put("address", server)
            .put("port", port)
            .put("public_key", publicKey)
            .put("allowed_ips", JSONArray(allowedIps))
        peer["presharedkey"]?.takeIf { it.isNotBlank() }?.let { peerConfig.put("pre_shared_key", it) }
        peer["persistentkeepalive"]?.toIntOrNull()?.takeIf { it > 0 }?.let {
            peerConfig.put("persistent_keepalive_interval", it)
        }

        val endpointConfig = JSONObject()
            .put("type", "wireguard")
            .put("tag", "proton-wireguard")
            .put("mtu", iface["mtu"]?.toIntOrNull()?.coerceIn(1280, 1500) ?: 1408)
            .put("address", JSONArray(localAddresses))
            .put("private_key", privateKey)
            .put("peers", JSONArray().put(peerConfig))

        val dnsServer = iface["dns"]?.split(',')?.map { it.trim() }?.firstOrNull { it.isNotBlank() } ?: "1.1.1.1"
        return JSONObject()
            .put("log", JSONObject().put("level", "debug").put("timestamp", true))
            .put("dns", JSONObject()
                .put("servers", JSONArray().put(JSONObject()
                    .put("type", "udp").put("tag", "wireguard-dns")
                    .put("server", dnsServer).put("server_port", 53)
                    .put("detour", "proton-wireguard")))
                .put("final", "wireguard-dns").put("strategy", "prefer_ipv4"))
            .put("inbounds", JSONArray()
                .put(JSONObject()
                    .put("type", "tun").put("tag", "tun-in")
                    .put("address", JSONArray().put("172.19.0.1/30").put("fdfe:dcba:9876::1/126"))
                    .put("mtu", 1408).put("auto_route", true).put("stack", "system"))
                .put(JSONObject().put("type", "mixed").put("tag", "smartvpn-local-probe")
                    .put("listen", "127.0.0.1").put("listen_port", 20808)))
            .put("outbounds", JSONArray().put(JSONObject().put("type", "direct").put("tag", "direct")))
            .put("endpoints", JSONArray().put(endpointConfig))
            .put("route", JSONObject()
                .put("auto_detect_interface", true)
                .put("final", "proton-wireguard"))
            .toString(2)
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
            val publicKey = q.getQueryParameter("pbk")
                ?: q.getQueryParameter("publicKey")
                ?: throw IllegalArgumentException("کلید عمومی Reality (pbk) در لینک وجود ندارد.")
            val reality = JSONObject().put("enabled", true)
                .put("public_key", publicKey)
            q.getQueryParameter("sid")?.takeIf { it.isNotBlank() }?.let { reality.put("short_id", it) }
            val fingerprint = q.getQueryParameter("fp")?.takeIf { it.isNotBlank() } ?: "chrome"
            tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", fingerprint))
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

    private fun decode(value: String): String = URLDecoder.decode(value.replace("+", "%2B"), "UTF-8")
    private fun pad(value: String): String = value + "=".repeat((4 - value.length % 4) % 4)
}
