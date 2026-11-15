package com.smartvpn.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.system.OsConstants
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.io.File
import java.util.concurrent.Executors

/**
 * Minimal Android host for libbox. The generated libbox interfaces are accessed
 * through reflection proxies so this app only implements the Android VPN
 * boundary it needs. Unknown optional platform callbacks return safe defaults.
 */
class SingBoxVpnService : VpnService() {
    private val worker = Executors.newSingleThreadExecutor()
    @Volatile private var commandServer: Any? = null
    @Volatile private var defaultNetworkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var platformProxy: Any? = null
    @Volatile private var activeConfig: String? = null
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var libboxSetup = false
    // Invalidates in-flight startup/verification when the user stops or replaces a connection.
    @Volatile private var operationGeneration = 0

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, notification("آماده‌سازی موتور VPN"))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            operationGeneration += 1
            activeConfig = null
            stopTunnel(notifyDisconnected = true)
            updateNotification("VPN قطع شد")
            stopSelf()
            return START_NOT_STICKY
        }
        val config = intent?.getStringExtra(EXTRA_CONFIG)
        if (config.isNullOrBlank()) {
            updateNotification("پیکربندی خالی است")
            stopSelf()
            return START_NOT_STICKY
        }
        val attemptGeneration = operationGeneration + 1
        operationGeneration = attemptGeneration
        activeConfig = config
        sendStatus("starting", null)
        updateNotification("در حال آماده‌سازی تونل VPN")
        worker.execute {
            try {
                if (!isCurrentAttempt(attemptGeneration)) return@execute
                if (commandServer != null) stopTunnel(notifyDisconnected = false)
                sendStatus("engine_starting", null)
                updateNotification("در حال راه‌اندازی موتور sing-box")
                startLibbox(config)
                if (!isCurrentAttempt(attemptGeneration)) {
                    Log.i(TAG, "Connection attempt cancelled after engine startup")
                    stopTunnel(notifyDisconnected = false)
                    return@execute
                }
                sendStatus("checking", null)
                updateNotification("تونل ایجاد شد؛ در حال بررسی عبور اینترنت")
                val probeFailure = verifyTunnelConnectivity()
                // A successful probe from an obsolete attempt must never publish CONNECTED.
                if (!isCurrentAttempt(attemptGeneration)) {
                    Log.i(TAG, "Connection attempt cancelled during connectivity verification")
                    stopTunnel(notifyDisconnected = false)
                    return@execute
                }
                if (probeFailure != null) throw IllegalStateException(probeFailure)
                getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_RUNNING, true).apply()
                updateNotification("VPN متصل و بررسی شد")
                sendStatus("connected", null)
            } catch (e: Exception) {
                if (!isCurrentAttempt(attemptGeneration)) {
                    Log.i(TAG, "Ignoring error from cancelled connection attempt", e)
                    stopTunnel(notifyDisconnected = false)
                    return@execute
                }
                val root = rootCause(e)
                val detail = "${root.javaClass.simpleName}: ${root.message ?: "بدون پیام خطا"}"
                Log.e(TAG, "Unable to start sing-box; root cause: $detail", root)
                Log.e(TAG, "Original reflection exception", e)
                getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_RUNNING, false).apply()
                updateNotification("خطا در اتصال: $detail")
                // Cleanup must not broadcast "disconnected" before the error reaches the UI.
                stopTunnel(notifyDisconnected = false)
                sendStatus("error", detail)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun isCurrentAttempt(generation: Int): Boolean = generation == operationGeneration

    private fun rootCause(error: Throwable): Throwable {
        var current = error
        val seen = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Throwable, Boolean>())
        while (seen.add(current)) {
            val next = when (current) {
                is java.lang.reflect.InvocationTargetException -> current.targetException ?: current.cause
                else -> current.cause
            } ?: break
            if (next === current) break
            current = next
        }
        return current
    }

    /**
     * Returns null only when an HTTPS request succeeds through the active VPN.
     * On failure, preserve per-endpoint diagnostics so the app log distinguishes
     * DNS, timeout, TLS and HTTP failures instead of reporting one generic error.
     */
    private fun verifyTunnelConnectivity(): String? {
        // Run both checks independently on every attempt. The local mixed inbound
        // validates the sing-box outbound; the direct socket validates Android TUN.
        // URLTest starts its initial outbound checks asynchronously at engine startup.
        // Allow the parallel HTTPS probes to populate latency history before the
        // local proxy/TUN acceptance checks choose the selected outbound.
        Thread.sleep(25000)

        val localFailures = mutableListOf<String>()
        var localProxySucceeded = false
        for (host in listOf("cp.cloudflare.com", "example.com", "www.microsoft.com")) {
            var raw: java.net.Socket? = null
            var tls: javax.net.ssl.SSLSocket? = null
            var phase = "LOCAL_PROXY_CONNECT"
            try {
                raw = java.net.Socket()
                raw.connect(java.net.InetSocketAddress("127.0.0.1", PROBE_PORT), 2500)
                raw.soTimeout = 5000

                phase = "PROXY_CONNECT"
                val request = "CONNECT " + host + ":443 HTTP/1.1\r\nHost: " +
                    host + ":443\r\nProxy-Connection: Keep-Alive\r\n\r\n"
                raw.getOutputStream().write(request.toByteArray(Charsets.US_ASCII))
                raw.getOutputStream().flush()
                val input = raw.getInputStream()
                val statusLine = readHttpLine(input)
                if (!statusLine.matches(Regex("""^HTTP/1\.[01]\s+2\d\d(?:\s.*)?$"""))) {
                    throw IllegalStateException("پاسخ CONNECT ناموفق: " + statusLine.take(160))
                }
                while (true) {
                    val header = readHttpLine(input)
                    if (header.isEmpty()) break
                }

                phase = "TLS_HANDSHAKE"
                tls = (javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory)
                    .createSocket(raw, host, 443, true) as javax.net.ssl.SSLSocket
                tls.soTimeout = 5000
                val parameters = tls.sslParameters
                parameters.endpointIdentificationAlgorithm = "HTTPS"
                parameters.serverNames = listOf(javax.net.ssl.SNIHostName(host))
                tls.sslParameters = parameters
                tls.startHandshake()

                phase = "HTTPS_REQUEST"
                val httpsRequest = "GET / HTTP/1.1\r\nHost: " + host +
                    "\r\nUser-Agent: SmartVPN-Android/0.7.9\r\nConnection: close\r\n\r\n"
                tls.outputStream.write(httpsRequest.toByteArray(Charsets.US_ASCII))
                tls.outputStream.flush()
                val response = readHttpLine(tls.inputStream)
                val code = Regex("""^HTTP/\d(?:\.\d)?\s+(\d{3})""")
                    .find(response)?.groupValues?.get(1)?.toIntOrNull()
                if (code != null && code in 200..399) {
                    Log.i(TAG, "Local sing-box outbound probe succeeded: " + host + " HTTP " + code)
                    localProxySucceeded = true
                    break
                }
                throw IllegalStateException("پاسخ HTTPS نامعتبر: " + response.take(160))
            } catch (e: Exception) {
                val root = rootCause(e)
                val detail = root.javaClass.simpleName + ": " + (root.message ?: "بدون پیام")
                localFailures += host + " [" + phase + "]: " + detail
                Log.w(TAG, "Local sing-box outbound probe failed at " + phase + " for " + host + ": " + detail, e)
            } finally {
                runCatching { tls?.close() }
                if (tls == null) runCatching { raw?.close() }
            }
        }

        // Do not return early when the local proxy fails: this test is deliberately
        // independent and must still tell us whether Android routes traffic through TUN.
        val tunFailure = verifyAndroidTunRouting()
        if (localProxySucceeded && tunFailure == null) {
            Log.i(TAG, "Both local outbound and Android TUN connectivity probes succeeded")
            return null
        }

        val failures = mutableListOf<String>()
        if (!localProxySucceeded) {
            failures += "آزمون خروجی محلی sing-box ناموفق بود؛ " + localFailures.joinToString(" | ")
        }
        if (tunFailure != null) failures += tunFailure
        return failures.joinToString(" || ")
    }

    private fun verifyAndroidTunRouting(): String? {
        // Use a numeric IPv4 endpoint so this test does not depend on Android DNS.
        // DNS is already exercised by the local sing-box proxy probe above.
        val host = "one.one.one.one"
        var raw: java.net.Socket? = null
        var tls: javax.net.ssl.SSLSocket? = null
        var phase = "ANDROID_TUN_CONNECT"
        try {
            val ip = java.net.InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1))
            raw = java.net.Socket()
            raw.connect(java.net.InetSocketAddress(ip, 443), 5000)
            raw.soTimeout = 5000

            phase = "ANDROID_TUN_TLS"
            tls = (javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory)
                .createSocket(raw, host, 443, true) as javax.net.ssl.SSLSocket
            tls.soTimeout = 5000
            val parameters = tls.sslParameters
            parameters.endpointIdentificationAlgorithm = "HTTPS"
            parameters.serverNames = listOf(javax.net.ssl.SNIHostName(host))
            tls.sslParameters = parameters
            tls.startHandshake()

            phase = "ANDROID_TUN_HTTPS"
            val request = "GET / HTTP/1.1\r\nHost: " + host +
                "\r\nUser-Agent: SmartVPN-Android/0.7.9-TUN\r\nConnection: close\r\n\r\n"
            tls.outputStream.write(request.toByteArray(Charsets.US_ASCII))
            tls.outputStream.flush()
            val response = readHttpLine(tls.inputStream)
            val code = Regex("""^HTTP/\d(?:\.\d)?\s+(\d{3})""")
                .find(response)?.groupValues?.get(1)?.toIntOrNull()
            if (code != null && code in 200..399) {
                Log.i(TAG, "Android TUN routing probe succeeded: " + host + " HTTP " + code)
                return null
            }
            throw IllegalStateException("پاسخ HTTPS نامعتبر: " + response.take(160))
        } catch (e: Exception) {
            val root = rootCause(e)
            val detail = root.javaClass.simpleName + ": " + (root.message ?: "بدون پیام")
            Log.w(TAG, "Android TUN routing probe failed at " + phase + ": " + detail, e)
            return "آزمون مستقل مسیر TUN اندروید در مرحله " +
                phase + " شکست خورد: " + detail
        } finally {
            runCatching { tls?.close() }
            if (tls == null) runCatching { raw?.close() }
        }
    }

    private fun readHttpLine(input: java.io.InputStream): String {
        val bytes = java.io.ByteArrayOutputStream()
        while (bytes.size() < 8192) {
            val value = input.read()
            if (value == -1 || value == 10) break
            if (value != 13) bytes.write(value)
        }
        return bytes.toString(Charsets.US_ASCII.name())
    }

    private fun startLibbox(config: String) {
        val loader = classLoader!!
        val libbox = Class.forName("io.nekohasekai.libbox.Libbox", true, loader)
        if (!libboxSetup) {
            val setupClass = Class.forName("io.nekohasekai.libbox.SetupOptions", true, loader)
            val setup = setupClass.getDeclaredConstructor().newInstance()
            setProperty(setup, "basePath", filesDir.absolutePath)
            setProperty(setup, "workingPath", getExternalFilesDir(null)?.absolutePath ?: filesDir.absolutePath)
            setProperty(setup, "tempPath", cacheDir.absolutePath)
            setProperty(setup, "debug", true)
            setProperty(setup, "logMaxLines", 1000)
            val setupMethod = libbox.methods.firstOrNull { it.name == "setup" && it.parameterCount == 1 }
                ?: throw IllegalStateException("libbox.setup در کتابخانه پیدا نشد")
            setupMethod.invoke(null, setup)
            libboxSetup = true
        }

        val platformType = Class.forName("io.nekohasekai.libbox.PlatformInterface", true, loader)
        val handlerType = Class.forName("io.nekohasekai.libbox.CommandServerHandler", true, loader)
        val platform = Proxy.newProxyInstance(loader, arrayOf(platformType), PlatformInvocation())
        val handler = Proxy.newProxyInstance(loader, arrayOf(handlerType), HandlerInvocation())
        platformProxy = platform

        val serverClass = Class.forName("io.nekohasekai.libbox.CommandServer", true, loader)
        val constructor = serverClass.constructors.firstOrNull {
            it.parameterTypes.size == 2 &&
                it.parameterTypes[0].isAssignableFrom(handlerType) &&
                it.parameterTypes[1].isAssignableFrom(platformType)
        } ?: serverClass.constructors.firstOrNull { it.parameterCount == 2 }
            ?: throw IllegalStateException("سازنده CommandServer پیدا نشد")
        val server = constructor.newInstance(handler, platform)
        commandServer = server
        val startMethod = serverClass.methods.firstOrNull { it.name == "start" && it.parameterCount == 0 }
            ?: throw IllegalStateException("متد شروع CommandServer پیدا نشد")
        startMethod.invoke(server)

        val overrideClass = Class.forName("io.nekohasekai.libbox.OverrideOptions", true, loader)
        val overrides = overrideClass.getDeclaredConstructor().newInstance()
        setProperty(overrides, "autoRedirect", false)
        val start = serverClass.methods.firstOrNull {
            it.name == "startOrReloadService" && it.parameterCount == 2
        } ?: throw IllegalStateException("متد startOrReloadService پیدا نشد")
        start.invoke(server, config, overrides)
    }

    private inner class HandlerInvocation : InvocationHandler {
        override fun invoke(proxy: Any, method: Method, args: Array<out Any?>?): Any? {
            when (method.name) {
                "serviceStop" -> { worker.execute { stopTunnel(notifyDisconnected = true); stopSelf() }; return null }
                "serviceReload" -> {
                    val config = activeConfig ?: return null
                    worker.execute { runCatching { reloadLibbox(config) }.onFailure { Log.e(TAG, "reload", it) } }
                    return null
                }
                "writeDebugMessage" -> {
                    val message = args?.firstOrNull()?.toString().orEmpty()
                    val lower = message.lowercase(java.util.Locale.ROOT)
                    if (listOf("error", "warn", "failed", "timeout", "dns", "connect", "tls", "protect", "route", "proxy").any { lower.contains(it) }) {
                        Log.w(TAG, "sing-box: " + message.take(450))
                        sendStatus("diagnostic", message.take(450))
                    }
                    return null
                }
                "triggerNativeCrash" -> return null
                "connectSSHAgent" -> return -1
                "getSystemProxyStatus" -> {
                    val type = Class.forName("io.nekohasekai.libbox.SystemProxyStatus")
                    return type.getDeclaredConstructor().newInstance()
                }
            }
            return defaultValue(method.returnType)
        }
    }

    private fun reloadLibbox(config: String) {
        val server = commandServer ?: return
        val type = server.javaClass
        val overrideClass = Class.forName("io.nekohasekai.libbox.OverrideOptions")
        val options = overrideClass.getDeclaredConstructor().newInstance()
        type.methods.first { it.name == "startOrReloadService" && it.parameterCount == 2 }
            .invoke(server, config, options)
    }

    private inner class PlatformInvocation : InvocationHandler {
        override fun invoke(proxy: Any, method: Method, args: Array<out Any?>?): Any? {
            when (method.name) {
                "openTun" -> return establishTun(args?.firstOrNull() ?: error("TunOptions موجود نیست"))
                "autoDetectInterfaceControl" -> {
                    val fd = (args?.firstOrNull() as? Number)?.toInt() ?: -1
                    if (fd >= 0 && !protect(fd)) throw IllegalStateException("محافظت سوکت VPN ناموفق بود")
                    return null
                }
                "usePlatformAutoDetectInterfaceControl" -> return true
                "underNetworkExtension", "includeAllNetworks", "usePlatformShell",
                "usePlatformBridge", "usePlatformAutoRedirect" -> return false
                "startDefaultInterfaceMonitor" -> {
                    val listener = args?.firstOrNull() ?: return null
                    startDefaultInterfaceMonitor(listener)
                    return null
                }
                "closeDefaultInterfaceMonitor" -> {
                    closeDefaultInterfaceMonitor()
                    return null
                }
                "clearDNSCache", "registerMyInterface", "closeNeighborMonitor" -> return null
                "getInterfaces" -> return networkInterfacesProxy()
                "findConnectionOwner" -> {
                    val type = Class.forName("io.nekohasekai.libbox.ConnectionOwner")
                    return type.getDeclaredConstructor().newInstance()
                }
                "readWIFIState", "localDNSTransport" -> return null
            }
            return defaultValue(method.returnType)
        }
    }

    private fun establishTun(options: Any): Int {
        tun?.close()
        val requestedMtu = readInt(options, "mtu", 1500)
        // Keep mobile TUN packets within a broadly compatible MTU.
        val safeMtu = requestedMtu.coerceIn(1280, 1500)
        val builder = Builder().setSession("SmartVPN").setMtu(safeMtu)
        Log.i(TAG, "TUN MTU: requested=$requestedMtu, applied=$safeMtu")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        addAddresses(builder, readValue(options, "inet4Address"))
        addAddresses(builder, readValue(options, "inet6Address"))
        val autoRoute = readBoolean(options, "autoRoute", true)
        if (autoRoute) {
            val dns = readValue(options, "dnsServerAddress")
            iterate(dns) { builder.addDnsServer(it.toString()) }
            addRoutes(builder, readValue(options, "inet4RouteAddress"))
            addRoutes(builder, readValue(options, "inet6RouteAddress"))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                addRoutes(builder, readValue(options, "inet4RouteExcludeAddress"), true)
                addRoutes(builder, readValue(options, "inet6RouteExcludeAddress"), true)
            }
            if (!hasRoutes(options, "inet4RouteAddress") && hasAddresses(options, "inet4Address")) {
                builder.addRoute("0.0.0.0", 0)
            }
            if (!hasRoutes(options, "inet6RouteAddress") && hasAddresses(options, "inet6Address")) {
                builder.addRoute("::", 0)
            }
        }
        val descriptor = builder.establish() ?: throw IllegalStateException("Android اجازه ایجاد تونل VPN را نداد")
        tun = descriptor
        return descriptor.fd
    }

    private fun addAddresses(builder: Builder, iterator: Any?) {
        iterate(iterator) { item ->
            val address = readString(item, "address")
            val prefix = readInt(item, "prefix", -1)
            if (address.isNotBlank() && prefix in 0..128) builder.addAddress(address, prefix)
        }
    }

    private fun addRoutes(builder: Builder, iterator: Any?, exclude: Boolean = false) {
        iterate(iterator) { item ->
            val address = readString(item, "address")
            val prefix = readInt(item, "prefix", -1)
            if (address.isNotBlank() && prefix in 0..128) {
                if (exclude && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    builder.excludeRoute(android.net.IpPrefix(java.net.InetAddress.getByName(address), prefix))
                } else builder.addRoute(address, prefix)
            }
        }
    }

    private fun hasAddresses(options: Any, name: String) = hasNext(readValue(options, name))
    private fun hasRoutes(options: Any, name: String) = hasNext(readValue(options, name))

    /**
     * Expose Android's actual active network metadata to libbox. Enumerating
     * java.net.NetworkInterface alone is insufficient: it does not provide
     * Android DNS servers, default gateways, transport type or metering state.
     */
    private fun networkInterfacesProxy(): Any {
        val entries = mutableListOf<Any>()
        val itemType = Class.forName("io.nekohasekai.libbox.NetworkInterface")
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val physicalByName = mutableMapOf<String, java.net.NetworkInterface>()
        val allPhysical = java.net.NetworkInterface.getNetworkInterfaces()
        while (allPhysical != null && allPhysical.hasMoreElements()) {
            val physical = allPhysical.nextElement()
            physicalByName[physical.name] = physical
        }

        for (network in connectivity.allNetworks) {
            val link = connectivity.getLinkProperties(network) ?: continue
            val capabilities = connectivity.getNetworkCapabilities(network) ?: continue
            // Exclude the VPN TUN itself: it is not an underlay and can cause recursive routing.
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                Log.i(TAG, "Ignoring VPN interface while enumerating underlay networks")
                continue
            }
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            val interfaceName = link.interfaceName ?: continue
            val physical = physicalByName[interfaceName]
                ?: runCatching { java.net.NetworkInterface.getByName(interfaceName) }.getOrNull()
                ?: continue
            if (physical.isLoopback || !runCatching { physical.isUp }.getOrDefault(false)) continue

            val item = itemType.getDeclaredConstructor().newInstance()
            setProperty(item, "name", interfaceName)
            setProperty(item, "index", physical.index)
            setProperty(item, "mtu", runCatching { physical.mtu }.getOrDefault(1500))

            val addresses = physical.interfaceAddresses.mapNotNull { entry ->
                val address = entry.address?.hostAddress?.substringBefore('%') ?: return@mapNotNull null
                "$address/${entry.networkPrefixLength}"
            }
            val dnsServers = link.dnsServers.mapNotNull { it.hostAddress?.substringBefore('%') }
            val searchDomains = link.domains?.split(' ')?.filter { it.isNotBlank() }.orEmpty()
            val gateways = link.routes
                .filter { it.destination.prefixLength == 0 }
                .mapNotNull { route -> route.gateway?.takeUnless { it.isAnyLocalAddress }?.hostAddress?.substringBefore('%') }

            var flags = 0
            if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                flags = flags or OsConstants.IFF_UP or OsConstants.IFF_RUNNING
            }
            if (physical.isLoopback) flags = flags or OsConstants.IFF_LOOPBACK
            if (physical.isPointToPoint) flags = flags or OsConstants.IFF_POINTOPOINT
            if (runCatching { physical.supportsMulticast() }.getOrDefault(false)) {
                flags = flags or OsConstants.IFF_MULTICAST
            }

            val interfaceType = when {
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> libboxInterfaceType("InterfaceTypeWIFI")
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> libboxInterfaceType("InterfaceTypeCellular")
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> libboxInterfaceType("InterfaceTypeEthernet")
                else -> libboxInterfaceType("InterfaceTypeOther")
            }

            setProperty(item, "addresses", stringIteratorProxy(addresses))
            setProperty(item, "dnsServer", stringIteratorProxy(dnsServers))
            setProperty(item, "dnsSearchDomain", stringIteratorProxy(searchDomains))
            setProperty(item, "gateway", stringIteratorProxy(gateways))
            setProperty(item, "flags", flags)
            setProperty(item, "metered", !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
            setProperty(item, "type", interfaceType)
            entries.add(item)
            Log.i(TAG, "Underlying network interface: $interfaceName; addresses=${addresses.size}, DNS=${dnsServers.size}, gateways=${gateways.size}, type=$interfaceType")
        }

        val iteratorType = Class.forName("io.nekohasekai.libbox.NetworkInterfaceIterator")
        val iterator = entries.iterator()
        return Proxy.newProxyInstance(classLoader, arrayOf(iteratorType)) { _, method, _ ->
            when (method.name) {
                "hasNext" -> iterator.hasNext()
                "next" -> if (iterator.hasNext()) iterator.next() else null
                else -> defaultValue(method.returnType)
            }
        }
    }

    private fun libboxInterfaceType(fieldName: String): Int = runCatching {
        Class.forName("io.nekohasekai.libbox.Libbox").getField(fieldName).getInt(null)
    }.getOrDefault(0)

    private fun startDefaultInterfaceMonitor(listener: Any) {
        val connectivity = getSystemService(ConnectivityManager::class.java)
        closeDefaultInterfaceMonitor()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                notifyDefaultInterface(listener, network, connectivity)
            }

            override fun onLost(network: Network) {
                notifyDefaultInterface(listener, connectivity.activeNetwork, connectivity)
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                if (network == connectivity.activeNetwork) {
                    notifyDefaultInterface(listener, network, connectivity)
                }
            }
        }
        defaultNetworkCallback = callback
        connectivity.registerDefaultNetworkCallback(callback)
        notifyDefaultInterface(listener, connectivity.activeNetwork, connectivity)
    }

    private fun closeDefaultInterfaceMonitor() {
        val callback = defaultNetworkCallback ?: return
        runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback) }
        defaultNetworkCallback = null
    }

    private fun notifyDefaultInterface(listener: Any, network: Network?, connectivity: ConnectivityManager) {
        runCatching {
            val method = listener.javaClass.methods.firstOrNull {
                it.name == "updateDefaultInterface" && it.parameterCount == 4
            } ?: return
            if (network == null) {
                method.invoke(listener, "", -1, false, false)
                return
            }

            var link = connectivity.getLinkProperties(network)
            var capabilities = connectivity.getNetworkCapabilities(network)
            val reportedName = link?.interfaceName.orEmpty()

            // Android may report the VPN itself (tun0) as activeNetwork. Passing
            // that virtual interface to sing-box makes it route its upstream through
            // the VPN itself instead of the physical network.
            if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true ||
                reportedName.startsWith("tun", ignoreCase = true)) {
                val underlay = connectivity.allNetworks.mapNotNull { candidate ->
                    val candidateCapabilities = connectivity.getNetworkCapabilities(candidate)
                        ?: return@mapNotNull null
                    if (candidateCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                        !candidateCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                        return@mapNotNull null
                    }
                    val candidateLink = connectivity.getLinkProperties(candidate)
                        ?: return@mapNotNull null
                    val candidateName = candidateLink.interfaceName ?: return@mapNotNull null
                    val physical = runCatching {
                        java.net.NetworkInterface.getByName(candidateName)
                    }.getOrNull() ?: return@mapNotNull null
                    if (physical.isLoopback || !runCatching { physical.isUp }.getOrDefault(false)) {
                        return@mapNotNull null
                    }
                    Triple(candidate, candidateLink, candidateCapabilities)
                }.sortedWith(
                    compareByDescending<Triple<Network, android.net.LinkProperties, NetworkCapabilities>> {
                        it.third.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                    }.thenBy {
                        !it.third.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
                    }
                ).firstOrNull()

                if (underlay == null) {
                    Log.w(TAG, "Active network is VPN ($reportedName), but no usable physical underlay was found")
                    method.invoke(listener, "", -1, false, false)
                    return
                }
                link = underlay.second
                capabilities = underlay.third
                Log.i(TAG, "Resolved VPN default interface $reportedName to physical underlay ${link.interfaceName}")
            }

            val name = link?.interfaceName.orEmpty()
            val index = runCatching {
                java.net.NetworkInterface.getByName(name)?.index ?: -1
            }.getOrDefault(-1)
            if (name.isBlank() || index < 0) {
                Log.w(TAG, "Ignoring invalid default interface update: name=$name index=$index")
                method.invoke(listener, "", -1, false, false)
                return
            }
            val metered = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
            method.invoke(listener, name, index, metered, false)
        }.onFailure { Log.w(TAG, "Unable to notify sing-box about default network", it) }
    }

    private fun stringIteratorProxy(values: List<String>): Any {
        val iteratorType = Class.forName("io.nekohasekai.libbox.StringIterator")
        val iterator = values.iterator()
        return Proxy.newProxyInstance(classLoader, arrayOf(iteratorType)) { _, method, _ ->
            when (method.name) {
                "hasNext" -> iterator.hasNext()
                "next" -> if (iterator.hasNext()) iterator.next() else ""
                "len" -> values.size
                else -> defaultValue(method.returnType)
            }
        }
    }
    private fun emptyIteratorProxy(interfaceName: String): Any {
        val type = Class.forName(interfaceName)
        return Proxy.newProxyInstance(classLoader, arrayOf(type)) { _, method, _ ->
            when (method.name) { "hasNext" -> false; "next" -> null; "len" -> 0; else -> defaultValue(method.returnType) }
        }
    }

    private fun iterate(value: Any?, action: (Any) -> Unit) {
        if (value == null) return
        val hasNext = value.javaClass.methods.firstOrNull { it.name == "hasNext" && it.parameterCount == 0 } ?: return
        val next = value.javaClass.methods.firstOrNull { it.name == "next" && it.parameterCount == 0 } ?: return
        while (runCatching { hasNext.invoke(value) as Boolean }.getOrDefault(false)) {
            val item = next.invoke(value) ?: break
            action(item)
        }
    }

    private fun hasNext(value: Any?): Boolean = runCatching {
        value?.javaClass?.methods?.firstOrNull { it.name == "hasNext" }?.invoke(value) as? Boolean ?: false
    }.getOrDefault(false)

    private fun readValue(target: Any, name: String): Any? {
        val cap = name.replaceFirstChar { it.uppercase() }
        val method = target.javaClass.methods.firstOrNull { it.name == "get$cap" || it.name == "is$cap" || it.name == name }
        return method?.invoke(target)
    }

    private fun readString(target: Any, name: String): String {
        val value = readValue(target, name)
        return value?.toString().orEmpty()
    }

    private fun readInt(target: Any, name: String, fallback: Int): Int =
        (readValue(target, name) as? Number)?.toInt() ?: fallback

    private fun readBoolean(target: Any, name: String, fallback: Boolean): Boolean =
        readValue(target, name) as? Boolean ?: fallback

    private fun setProperty(target: Any, name: String, value: Any) {
        val cap = name.replaceFirstChar { it.uppercase() }
        val setter = target.javaClass.methods.firstOrNull { it.name == "set$cap" && it.parameterCount == 1 }
        if (setter != null) runCatching { setter.invoke(target, value) }
    }

    private fun defaultValue(type: Class<*>): Any? = when (type) {
        java.lang.Boolean.TYPE -> false
        java.lang.Integer.TYPE -> 0
        java.lang.Long.TYPE -> 0L
        java.lang.Float.TYPE -> 0f
        java.lang.Double.TYPE -> 0.0
        java.lang.Void.TYPE -> null
        else -> null
    }

    private fun stopTunnel(notifyDisconnected: Boolean = false) {
        runCatching {
            commandServer?.let { server ->
                server.javaClass.methods.firstOrNull { it.name == "closeService" && it.parameterCount == 0 }?.invoke(server)
                server.javaClass.methods.firstOrNull { it.name == "close" && it.parameterCount == 0 }?.invoke(server)
            }
        }.onFailure { Log.w(TAG, "close libbox", it) }
        commandServer = null
        tun?.close()
        tun = null
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_RUNNING, false).apply()
        if (notifyDisconnected) sendStatus("disconnected", null)
    }

    private fun sendStatus(state: String, error: String?) {
        val detail = when (state) {
            "starting" -> "سرویس VPN شروع به کار کرد"
            "engine_starting" -> "موتور sing-box در حال راه‌اندازی است"
            "checking" -> "تونل ساخته شد؛ بررسی عبور اینترنت آغاز شد"
            "connected" -> "تونل فعال شد و عبور اینترنت تأیید شد"
            "disconnected" -> "تونل قطع شد"
            "error" -> "خطای تونل: ${error ?: "نامشخص"}"
            "diagnostic" -> "sing-box: ${error ?: "بدون جزئیات"}"
            else -> "وضعیت سرویس: $state"
        }
        EventLog.append(this, detail)
        sendBroadcast(Intent(ACTION_STATUS).setPackage(packageName).putExtra("state", state).putExtra("error", error))
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "SmartVPN", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun notification(message: String): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
        return builder.setContentTitle("SmartVPN").setContentText(message)
            .setSmallIcon(android.R.drawable.stat_sys_warning).setOngoing(true).build()
    }

    private fun updateNotification(message: String) {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(message))
    }

    override fun onRevoke() {
        stopTunnel(notifyDisconnected = true)
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        operationGeneration += 1
        stopTunnel(notifyDisconnected = false)
        closeDefaultInterfaceMonitor()
        worker.shutdownNow()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    companion object {
        const val ACTION_STOP = "com.smartvpn.android.STOP"
        const val ACTION_STATUS = "com.smartvpn.android.STATUS"
        const val EXTRA_CONFIG = "sing_box_config"
        private const val TAG = "SmartVPN"
        private const val CHANNEL_ID = "smartvpn_tunnel"
        private const val NOTIFICATION_ID = 2401
        private const val PREFS = "smartvpn_storage"
        private const val KEY_RUNNING = "vpn_running"
        private const val PROBE_PORT = 20808
    }
}
