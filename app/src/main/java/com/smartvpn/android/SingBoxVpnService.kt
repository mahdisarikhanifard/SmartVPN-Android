package com.smartvpn.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
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
    @Volatile private var platformProxy: Any? = null
    @Volatile private var activeConfig: String? = null
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var libboxSetup = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, notification("آماده‌سازی موتور VPN"))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        val config = intent?.getStringExtra(EXTRA_CONFIG)
        if (config.isNullOrBlank()) {
            updateNotification("پیکربندی خالی است")
            stopSelf()
            return START_NOT_STICKY
        }
        activeConfig = config
        worker.execute {
            try {
                if (commandServer != null) stopTunnel()
                startLibbox(config)
                getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_RUNNING, true).apply()
                updateNotification("VPN فعال است")
                sendStatus("connected", null)
            } catch (e: Exception) {
                Log.e(TAG, "Unable to start sing-box", e)
                getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_RUNNING, false).apply()
                updateNotification("خطا در اتصال: ${e.message ?: "نامشخص"}")
                sendStatus("error", e.message ?: e.javaClass.simpleName)
                stopTunnel()
                stopSelf()
            }
        }
        return START_NOT_STICKY
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
            setProperty(setup, "debug", false)
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
                "serviceStop" -> { worker.execute { stopTunnel(); stopSelf() }; return null }
                "serviceReload" -> {
                    val config = activeConfig ?: return null
                    worker.execute { runCatching { reloadLibbox(config) }.onFailure { Log.e(TAG, "reload", it) } }
                    return null
                }
                "writeDebugMessage" -> { Log.d(TAG, args?.firstOrNull()?.toString() ?: "libbox"); return null }
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
                "startDefaultInterfaceMonitor", "closeDefaultInterfaceMonitor",
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
        val builder = Builder().setSession("SmartVPN").setMtu(readInt(options, "mtu", 9000))
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

    private fun networkInterfacesProxy(): Any {
        val entries = mutableListOf<Any>()
        val type = Class.forName("io.nekohasekai.libbox.NetworkInterface")
        val all = java.net.NetworkInterface.getNetworkInterfaces()
        while (all != null && all.hasMoreElements()) {
            val physical = all.nextElement()
            if (physical.isLoopback || !runCatching { physical.isUp }.getOrDefault(false)) continue
            val item = type.getDeclaredConstructor().newInstance()
            setProperty(item, "name", physical.name)
            setProperty(item, "index", physical.index)
            setProperty(item, "mtu", runCatching { physical.mtu }.getOrDefault(1500))
            val addresses = physical.interfaceAddresses.mapNotNull { entry ->
                val address = entry.address?.hostAddress ?: return@mapNotNull null
                "$address/${entry.networkPrefixLength}"
            }
            setProperty(item, "addresses", stringIteratorProxy(addresses))
            setProperty(item, "dnsServer", stringIteratorProxy(emptyList()))
            setProperty(item, "dnsSearchDomain", stringIteratorProxy(emptyList()))
            setProperty(item, "gateway", stringIteratorProxy(emptyList()))
            setProperty(item, "flags", 65)
            setProperty(item, "metered", false)
            setProperty(item, "type", 0)
            entries.add(item)
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

    private fun stopTunnel() {
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
        sendStatus("disconnected", null)
    }

    private fun sendStatus(state: String, error: String?) {
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
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
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
    }
}
