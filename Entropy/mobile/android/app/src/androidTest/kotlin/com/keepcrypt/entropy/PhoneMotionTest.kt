package com.keepcrypt.entropy

import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.waitUntil
import com.keepcrypt.entropy.screens.Screen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * PhoneMotion, the motion-source seam's Android end (SensorMotionSource.kt; tasks/todo.md, M5 group
 * 15; lead decision M5-51), on the emulator's own sensors, run by scripts/android-instrument.sh on the
 * shipping app in the API 31 and 36 legs. The app is in front, as it is whenever Device entropy runs
 * PhoneMotion (Android delivers no continuous sensor's events to an idle app). A probe line names the
 * sensors the image lists. The test listens to the same default accelerometer and gyroscope itself,
 * then starts a PhoneMotion on the main thread, as the ceremony model does:
 *
 * - within 5 s it reports an accelerometer sample, and a gyroscope sample where the image lists a
 *   gyroscope;
 * - every sample has the layout SensorMotionSource.kt gives it (commit 16's proof line): the sensor's
 *   type (4 bytes), the event's timestamp in nanoseconds (8) and each of its three values' bits (4
 *   each), big-endian, 24 bytes, with its type one of the two sensors'; and for each sensor at least
 *   one sample, read back in that layout, is an event the test's own listener received: the same
 *   type, the same timestamp and the same bits in every value;
 * - after stop no sample arrives for a second, while the test's own listener still receives events;
 * - and PhoneMotion unregistered, not only stopped reporting (stop drops its receiver before it
 *   unregisters, so the missing late samples cannot show it): Android opens a listener's sensor
 *   connection under the listener's class name (its enclosing class's for an anonymous one), and
 *   dumpsys sensorservice starts each connection's line with that name and " | ". Where it lists both
 *   PhoneMotion's connection and the test's own while PhoneMotion runs, after stop it lists the
 *   test's own and not PhoneMotion's; where it does not, a probe line says the unregistration is not
 *   proven on that image, and the pass line does not claim it.
 */
@RunWith(AndroidJUnit4::class)
class PhoneMotionTest {
    @Test
    fun samplesComeWithinFiveSecondsInTheirLayoutAndNoneAfterStop() {
        val context = Capture.instrumentation.targetContext
        val sensors = checkNotNull(context.getSystemService(SensorManager::class.java))
        val accelerometer = sensors.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        val gyroscope = sensors.getDefaultSensor(Sensor.TYPE_GYROSCOPE)
        val all = sensors.getSensorList(Sensor.TYPE_ALL)
        probe(
            "motion sensors: accelerometer ${accelerometer?.name ?: "not listed"}; gyroscope ${gyroscope?.name ?: "not listed"}; " +
                "the image lists ${all.size} sensors: " + all.joinToString("; ") { "${it.name} (type ${it.type})" },
        )
        assertTrue("the image lists no accelerometer", accelerometer != null)
        val listed = listOfNotNull(accelerometer, gyroscope)
        val types = listed.map { it.type }

        val activity = launch()
        waitUntil("the first screen, First launch") { onMain { activity.shownScreen } == Screen.FirstLaunch }

        // The test's own listener on the same sensors: each event's type, timestamp and value bits, on
        // the main thread.
        val own = HashMap<Pair<Int, Long>, IntArray>()
        val listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                own[Pair(event.sensor.type, event.timestamp)] = IntArray(event.values.size) { event.values[it].toRawBits() }
            }

            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {}
        }
        val main = Handler(Looper.getMainLooper())
        for (sensor in listed) {
            val registered = sensors.registerListener(listener, sensor, SensorManager.SENSOR_DELAY_GAME, main)
            assertTrue("the test's own listener was refused", registered)
        }

        // PhoneMotion, started and stopped on the main thread; each sample kept, with the time of each
        // sensor's first one after the start.
        val motion = PhoneMotion(context)
        val samples = ArrayList<ByteArray>()
        val first = HashMap<Int, Long>()
        onMain {
            val begun = SystemClock.elapsedRealtime()
            motion.start { sample ->
                samples.add(sample)
                if (sample.size >= 4) {
                    val type = bigEndian(sample, 0, 4).toInt()
                    if (!first.containsKey(type)) first[type] = SystemClock.elapsedRealtime() - begun
                }
            }
        }
        val end = SystemClock.elapsedRealtime() + FIRST_SAMPLE_MS
        while (!onMain { types.all { first.containsKey(it) } } && SystemClock.elapsedRealtime() < end) {
            SystemClock.sleep(50)
        }
        SystemClock.sleep(MORE_MS)
        val running = connections()
        val kept = onMain {
            motion.stop()
            ArrayList(samples)
        }
        val ownAtStop = onMain { own.size }
        SystemClock.sleep(AFTER_STOP_MS)
        val late = onMain { samples.size } - kept.size
        val ownAfterStop = onMain { own.size } - ownAtStop
        val stopped = connections()
        sensors.unregisterListener(listener)
        val events = onMain { HashMap(own) }
        finish(activity)

        // Each sample read back in its layout, and matched against the test's own events.
        val matched = HashMap<Int, Int>()
        for (sample in kept) {
            assertEquals("a sample is not 4 + 8 + 3 x 4 bytes", SAMPLE_BYTES, sample.size)
            val type = bigEndian(sample, 0, 4).toInt()
            assertTrue("a sample's type is neither listed sensor's: " + type, type in types)
            val bits = events[Pair(type, bigEndian(sample, 4, 8))] ?: continue
            if (bits.size == VALUES && (0 until VALUES).all { bigEndian(sample, 12 + 4 * it, 4).toInt() == bits[it] }) {
                matched[type] = (matched[type] ?: 0) + 1
            }
        }
        probe(
            "PhoneMotion: first accelerometer sample after ${first[Sensor.TYPE_ACCELEROMETER]} ms, first gyroscope sample after " +
                "${first[Sensor.TYPE_GYROSCOPE]} ms (null: none); ${kept.size} samples, " +
                "${matched[Sensor.TYPE_ACCELEROMETER] ?: 0} accelerometer and ${matched[Sensor.TYPE_GYROSCOPE] ?: 0} gyroscope ones " +
                "matching the test's own events; ${events.size} own events; in the second after stop $late samples and " +
                "$ownAfterStop own events",
        )
        for (type in types) {
            val name = if (type == Sensor.TYPE_ACCELEROMETER) "accelerometer" else "gyroscope"
            val after = first[type]
            assertTrue("no " + name + " sample within 5 s", after != null && after <= FIRST_SAMPLE_MS)
            assertTrue("no " + name + " sample is an event the test's own listener received, read in the layout", (matched[type] ?: 0) > 0)
        }
        assertEquals("a sample arrived after stop", 0, late)
        assertTrue("the sensors sent no event in the second after stop, so no sample there proves nothing", ownAfterStop > 0)

        // The unregistration, read where dumpsys lists both connections by name while PhoneMotion runs.
        val phoneMotion = connectionName(motion)
        val mine = connectionName(listener)
        val listed = phoneMotion != mine && phoneMotion in running && mine in running
        probe(
            "dumpsys sensorservice: while PhoneMotion ran it listed PhoneMotion's connection ($phoneMotion): " +
                "${phoneMotion in running}, the test's own ($mine): ${mine in running}; after stop PhoneMotion's: " +
                "${phoneMotion in stopped}, the test's own: ${mine in stopped}",
        )
        if (listed) {
            assertTrue("the test's own connection is not listed after stop, so PhoneMotion's absence proves nothing", mine in stopped)
            assertFalse("PhoneMotion's sensor connection is still listed after stop: it never unregistered", phoneMotion in stopped)
        } else {
            probe("dumpsys sensorservice does not list both connections by name on this image: the unregistration is not proven here")
        }
        val gyro = if (gyroscope != null) " and a gyroscope sample" else " (no gyroscope listed)"
        val unregistered = if (listed) "; unregistered (its connection listed while it ran, gone after stop)" else ""
        pass(
            "PhoneMotion: an accelerometer sample within 5 s" + gyro + ", each 24 bytes (type, timestamp, value bits, " +
                "big-endian) and matching the test's own events; none after stop" + unregistered,
        )
    }

    /**
     * The name Android opens listener's sensor connection under, as SystemSensorManager makes it: the
     * name of its enclosing class where it has one (an anonymous or nested listener), else its own.
     */
    private fun connectionName(listener: Any): String = (listener.javaClass.enclosingClass ?: listener.javaClass).name

    /**
     * The names that start lines of dumpsys sensorservice with " | " after them: every sensor
     * connection's name (a sensor's own line under its connection gives its handle there instead).
     */
    private fun connections(): Set<String> =
        Capture.shellText("dumpsys sensorservice").lines().mapNotNull { CONNECTION.find(it)?.groupValues?.get(1) }.toSet()

    /** The size bytes of bytes from at, big-endian. */
    private fun bigEndian(bytes: ByteArray, at: Int, size: Int): Long {
        var value = 0L
        for (index in 0 until size) value = (value shl 8) or (bytes[at + index].toLong() and 0xFF)
        return value
    }

    private companion object {
        /** The accelerometer's and the gyroscope's value count: three axes. */
        const val VALUES = 3

        /** A sample: the type (4 bytes), the timestamp (8) and three values (4 each). */
        const val SAMPLE_BYTES = 4 + 8 + 4 * VALUES

        /** How long the first sample of each sensor may take (lead decision M5-51). */
        const val FIRST_SAMPLE_MS = 5_000L

        /** How long PhoneMotion runs after both first samples, so the layout is read on more than one. */
        const val MORE_MS = 1_000L

        /** How long the test waits for a late sample after stop. */
        const val AFTER_STOP_MS = 1_000L

        /** A line of dumpsys sensorservice that starts with a name and " | ", the name captured. */
        val CONNECTION = Regex("""^\s*(\S+) \| """)
    }
}
