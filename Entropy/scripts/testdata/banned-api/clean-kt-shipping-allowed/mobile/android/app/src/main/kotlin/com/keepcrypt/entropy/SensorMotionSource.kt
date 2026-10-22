// The Android end of the motion-source seam: the one file that reads the sensors.
val sensors = context.getSystemService(SensorManager::class.java)
class Motion : SensorEventListener {
