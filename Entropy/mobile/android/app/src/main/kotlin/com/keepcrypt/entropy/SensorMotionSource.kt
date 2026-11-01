package com.keepcrypt.entropy

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Handler
import android.os.Looper
import com.keepcrypt.entropy.screens.MotionSource

/**
 * The Android end of the motion-source seam (tasks/todo.md, M5 group 15; lead decision M5-20;
 * docs/mobile-apps.md, "Entropy sources on phones": SensorManager's accelerometer and gyroscope, mixed
 * into the pool with no credit while Device entropy shows). The gate allows the sensor classes in this
 * file alone (KtDevice). Each event becomes one sample, reported on the main thread: the sensor's
 * type (4 bytes), the event's timestamp in nanoseconds (8) and each value's bits (4 each), big-endian;
 * the model hands it to core and zeroes it, and nothing logs it. The events come at
 * SENSOR_DELAY_GAME, about 50 a second, below the 200 Hz above which Android 12 wants
 * HIGH_SAMPLING_RATE_SENSORS, so the app asks for no permission (rule 9's manifest is unchanged). A
 * phone without one of the two sensors gives the other's samples alone: they carry no credit, so
 * nothing rests on them.
 */
internal class PhoneMotion(context: Context) : MotionSource, SensorEventListener {
    private val sensors = checkNotNull(context.getSystemService(SensorManager::class.java))
    private val main = Handler(Looper.getMainLooper())
    private var report: ((ByteArray) -> Unit)? = null

    /** Registers for both sensors' events, on the main thread, until stop. */
    override fun start(report: (sample: ByteArray) -> Unit) {
        stop()
        this.report = report
        for (type in TYPES) {
            val sensor = sensors.getDefaultSensor(type) ?: continue
            sensors.registerListener(this, sensor, SensorManager.SENSOR_DELAY_GAME, main)
        }
    }

    /** Unregisters; an event already queued finds no receiver and is dropped. */
    override fun stop() {
        if (report == null) return
        report = null
        sensors.unregisterListener(this)
    }

    override fun onSensorChanged(event: SensorEvent) {
        val receiver = report ?: return
        val values = event.values
        val sample = ByteArray(12 + 4 * values.size)
        put(sample, 0, event.sensor.type.toLong(), 4)
        put(sample, 4, event.timestamp, 8)
        for (index in values.indices) put(sample, 12 + 4 * index, values[index].toRawBits().toLong(), 4)
        receiver(sample)
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}

    private companion object {
        /** The two motion sensors MA names. */
        val TYPES = intArrayOf(Sensor.TYPE_ACCELEROMETER, Sensor.TYPE_GYROSCOPE)
    }
}

/** The low size bytes of value, big-endian, into bytes from at. */
private fun put(bytes: ByteArray, at: Int, value: Long, size: Int) {
    for (index in 0 until size) bytes[at + index] = (value ushr (8 * (size - 1 - index))).toByte()
}
