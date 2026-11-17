package com.keepcrypt.entropy.camera

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.hardware.camera2.CameraAccessException
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CameraMetadata
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.util.Size
import androidx.activity.result.ActivityResultLauncher
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.keepcrypt.entropy.screens.QrScanner
import com.keepcrypt.entropy.screens.ScanStop
import java.nio.ByteBuffer
import java.util.concurrent.Executor
import kotlin.concurrent.Volatile

/** The longest go-ahead QR text (swb:144: the largest QR alphanumeric capacity); a longer one is dropped. */
internal const val MAX_GO_AHEAD_TEXT = 4_296

/** The largest frame the scanner takes, by area: 1920x1080. */
private const val MAX_FRAME_AREA = 1920L * 1080

/**
 * ZXing's hints for a photo of a screen: QR codes only, searched for hard (TRY_HARDER), at any
 * rotation, and not read as a pure barcode, which only a rendered matrix is (QrRoundTripTest's).
 */
private val HINTS = mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE), DecodeHintType.TRY_HARDER to true)

/**
 * One YUV_420_888 frame's Y plane reduced to luminance (tasks/todo.md, M5 group 16): into's first
 * width x height bytes, a byte per pixel, row by row with no padding, read from plane's position at
 * its row and pixel strides (YUV_420_888's Y plane has pixel stride 1, but any is read right), plane
 * itself left as it was. A plane too short for its strides, or into too small, is the platform's or the
 * caller's bug, and fails. The scanner's frames come here on its own thread, and GoAheadFrameTest's
 * canned ones on the JVM.
 */
internal fun reduceLuminance(plane: ByteBuffer, rowStride: Int, pixelStride: Int, width: Int, height: Int, into: ByteArray) {
    check(width > 0 && height > 0 && pixelStride > 0 && rowStride >= (width - 1) * pixelStride + 1)
    check(into.size >= width * height)
    check(plane.remaining() >= (height - 1) * rowStride + (width - 1) * pixelStride + 1)
    val rows = plane.duplicate()
    val base = rows.position()
    for (y in 0 until height) {
        val start = base + y * rowStride
        if (pixelStride == 1) {
            rows.position(start)
            rows.get(into, y * width, width)
        } else {
            for (x in 0 until width) into[y * width + x] = rows.get(start + x * pixelStride)
        }
    }
}

/**
 * The go-ahead QR scanner's decode step (tasks/todo.md, M5 group 16; commit 14's GoAheadPngTest reads the
 * two go-ahead PNGs back with it): one frame's luminance, a byte per pixel, row by row with no padding,
 * to the text of the QR code ZXing core finds in it, at any rotation. ZXing throws a ReaderException
 * when the frame holds no QR code it can read; the luminance is zeroed before this returns or throws,
 * so no frame outlives its decode.
 */
internal fun decodeGoAhead(luminance: ByteArray, width: Int, height: Int): String {
    val source = PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false)
    try {
        return QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), HINTS).text
    } finally {
        luminance.fill(0)
    }
}

/**
 * The go-ahead QR text one frame's luminance holds, for the model's onGoAheadText; null for a frame
 * that holds none ZXing can read, which ZXing says by throwing a ReaderException (its NotFoundException,
 * ChecksumException or FormatException): the scanner's one catch of it drops that frame, its luminance
 * already zeroed (decodeGoAhead), and the next one is read (lead decision M5-53). A text over
 * MAX_GO_AHEAD_TEXT characters is dropped the same way (swb:144), before core sees it.
 */
internal fun goAheadText(luminance: ByteArray, width: Int, height: Int): String? {
    val text = try {
        decodeGoAhead(luminance, width, height)
    } catch (none: ReaderException) {
        return null
    }
    return if (text.length > MAX_GO_AHEAD_TEXT) null else text
}

/**
 * The Android end of the scanner seam (tasks/todo.md, M5 group 16 and "Built into this plan", Camera;
 * lead decision M5-20; docs/mobile-apps.md, step 9): Camera2 into an ImageReader, with no preview, so
 * nothing the camera sees is drawn and the window keeps FLAG_SECURE as its one surface. The gate allows
 * the camera's classes in this file alone (KtDevice), and here alone a catch of CameraAccessException
 * and of ReaderException (KtFailOpen, lead decision M5-53).
 *
 * - start asks for CAMERA through MainActivity's prompt (permission, registered in its onCreate) each
 *   time the scan screen starts a scan, and only then, a phone without a camera included; a refusal
 *   ends the scan (Refused).
 * - Granted, the scan runs on the scanner's own HandlerThread: the back camera, or else the first that
 *   gives YUV_420_888 frames (none, or no camera: Missing), at its largest YUV_420_888 size up to
 *   1920x1080 by area, with continuous autofocus where it is offered, into an ImageReader of two images.
 *   Each frame the reader has (acquireLatestImage, which drops stale ones) is reduced to luminance
 *   (reduceLuminance) and handed back, then decoded (goAheadText); the first text ends the scan and goes
 *   to found, once. A camera that cannot be opened or that fails ends the scan (Failed).
 * - Every Camera2 call runs on that thread behind the scan's own stop flag (step), and the scan's
 *   release runs there too, after any call already queued, so no call reaches a closed device, session
 *   or reader: their IllegalStateException is avoided, not caught. A device or session that arrives
 *   after the scan ended is closed at once.
 * - stop (the scan screen leaving or covered, the app left) ends the scan at once: nothing reaches found
 *   or stopped after it. No frame, luminance or text is logged, stored or kept: the luminance buffer is
 *   zeroed after each frame and at the end, the camera's image goes back to the reader as soon as it is
 *   reduced, and the text is handed over once.
 */
internal class GoAheadScanner(private val context: Context) : QrScanner {
    /** MainActivity's CAMERA prompt, registered in its onCreate; its answer comes to answered. */
    lateinit var permission: ActivityResultLauncher<String>

    private val main = Handler(Looper.getMainLooper())

    /** The scanner's thread, started for the first scan that opens the camera, until shutDown. Main thread only. */
    private var thread: HandlerThread? = null
    private var handler: Handler? = null

    /** The scan running, from start until its end or stop. Main thread only. */
    private var scan: Scan? = null

    /** A new scan, after any running one stops: the prompt first (the system's, while the app does not hold CAMERA). */
    override fun start(found: (text: String) -> Unit, stopped: (why: ScanStop) -> Unit) {
        stop()
        scan = Scan(found, stopped)
        permission.launch(Manifest.permission.CAMERA)
    }

    /**
     * The prompt's answer, on the main thread: granted, the scan opens the camera on the scanner's
     * thread; refused, it ends (Refused). An answer for a scan that stopped meanwhile goes nowhere.
     */
    fun answered(granted: Boolean) {
        val current = scan ?: return
        if (!current.asking) return
        current.asking = false
        if (!granted) {
            scan = null
            current.stopped(ScanStop.Refused)
            return
        }
        val camera = scannerThread()
        camera.post { current.open(camera) }
    }

    override fun stop() {
        val current = scan ?: return
        scan = null
        current.end()
    }

    /** The activity's end (MainActivity's onDestroy): the scan stopped, and the thread quits once its queue is done. */
    fun shutDown() {
        stop()
        thread?.quitSafely()
        thread = null
        handler = null
    }

    private fun scannerThread(): Handler {
        handler?.let { return it }
        val started = HandlerThread("go-ahead scanner")
        started.start()
        thread = started
        return Handler(started.looper).also { handler = it }
    }

    /** A camera's largest YUV_420_888 frame size up to MAX_FRAME_AREA; null when it gives none. */
    private fun largestFrame(facts: CameraCharacteristics): Size? {
        val sizes = facts.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)?.getOutputSizes(ImageFormat.YUV_420_888)
            ?: return null
        return sizes.filter { it.width.toLong() * it.height <= MAX_FRAME_AREA }.maxByOrNull { it.width.toLong() * it.height }
    }

    /** The camera a scan opens: its id and frame size, whether it faces back, and whether it offers continuous autofocus. */
    private class Choice(val id: String, val size: Size, val back: Boolean, val autofocus: Boolean)

    /**
     * One scan. asking, found and stopped are the main thread's; ended is set once, by stop on the main
     * thread or by the scan's own end on the scanner's thread; everything else is the scanner's thread's.
     */
    private inner class Scan(val found: (String) -> Unit, val stopped: (ScanStop) -> Unit) {
        /** Waiting for the prompt's answer. */
        var asking = true

        @Volatile
        private var ended = false

        private var device: CameraDevice? = null
        private var session: CameraCaptureSession? = null
        private var reader: ImageReader? = null
        private var luminance = ByteArray(0)
        private var width = 0
        private var height = 0
        private var autofocus = false

        /** stop's end, on the main thread: no step runs after this, and the release follows any step already queued. */
        fun end() {
            ended = true
            asking = false
            handler?.post { release() }
        }

        /** On the scanner's thread, every Camera2 call: block, unless the scan ended; a camera that fails ends it (Failed). */
        private fun step(block: () -> Unit) {
            if (ended) return
            try {
                block()
            } catch (failed: CameraAccessException) {
                finish { stopped(ScanStop.Failed) }
            }
        }

        /** The scan's own end, on the scanner's thread: everything released, then report on the main thread, unless stop came first. */
        private fun finish(report: () -> Unit) {
            ended = true
            release()
            main.post {
                if (scan === this@Scan) {
                    scan = null
                    report()
                }
            }
        }

        /** After the prompt's yes, on the scanner's thread: the camera chosen, its frames' reader made, the camera opened. */
        fun open(camera: Handler) = step {
            val cameras = context.getSystemService(CameraManager::class.java)
            val chosen = if (cameras != null && context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) {
                choose(cameras)
            } else {
                null
            }
            if (cameras == null || chosen == null) {
                finish { stopped(ScanStop.Missing) }
                return@step
            }
            width = chosen.size.width
            height = chosen.size.height
            autofocus = chosen.autofocus
            luminance = ByteArray(width * height)
            val frames = ImageReader.newInstance(width, height, ImageFormat.YUV_420_888, 2)
            reader = frames
            frames.setOnImageAvailableListener({ step { frame(it) } }, camera)
            cameras.openCamera(chosen.id, deviceCallback(camera), camera)
        }

        /** The back camera, or else the first, that gives YUV_420_888 frames; null for none. */
        private fun choose(cameras: CameraManager): Choice? {
            var best: Choice? = null
            for (id in cameras.cameraIdList) {
                val facts = cameras.getCameraCharacteristics(id)
                val size = largestFrame(facts) ?: continue
                val back = facts.get(CameraCharacteristics.LENS_FACING) == CameraMetadata.LENS_FACING_BACK
                if (best == null || (back && !best.back)) {
                    val modes = facts.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES)
                    val continuous = modes != null && modes.contains(CameraMetadata.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                    best = Choice(id, size, back, continuous)
                }
            }
            return best
        }

        private fun deviceCallback(camera: Handler) = object : CameraDevice.StateCallback() {
            override fun onOpened(opened: CameraDevice) {
                if (ended) {
                    opened.close()
                    return
                }
                device = opened
                step { configure(opened, camera) }
            }

            override fun onDisconnected(lost: CameraDevice) {
                lost.close()
                step { finish { stopped(ScanStop.Failed) } }
            }

            override fun onError(failed: CameraDevice, error: Int) {
                failed.close()
                step { finish { stopped(ScanStop.Failed) } }
            }
        }

        /** The capture session: the reader's surface alone, its callbacks on the scanner's thread. */
        private fun configure(opened: CameraDevice, camera: Handler) {
            val frames = reader ?: return
            val outputs = listOf(OutputConfiguration(frames.surface))
            val callbacks = Executor { camera.post(it) }
            opened.createCaptureSession(SessionConfiguration(SessionConfiguration.SESSION_REGULAR, outputs, callbacks, sessionCallback(camera)))
        }

        private fun sessionCallback(camera: Handler) = object : CameraCaptureSession.StateCallback() {
            override fun onConfigured(configured: CameraCaptureSession) {
                if (ended) {
                    configured.close()
                    return
                }
                session = configured
                step { stream(configured, camera) }
            }

            override fun onConfigureFailed(failed: CameraCaptureSession) {
                failed.close()
                step { finish { stopped(ScanStop.Failed) } }
            }
        }

        /** Frames into the reader, repeatedly, with continuous autofocus where the camera offers it. */
        private fun stream(configured: CameraCaptureSession, camera: Handler) {
            val opened = device ?: return
            val frames = reader ?: return
            val request = opened.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW)
            request.addTarget(frames.surface)
            if (autofocus) request.set(CaptureRequest.CONTROL_AF_MODE, CameraMetadata.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
            configured.setRepeatingRequest(request.build(), null, camera)
        }

        /** The reader's latest frame (older ones dropped), reduced to luminance and handed back at once, then decoded. */
        private fun frame(frames: ImageReader) {
            val image = frames.acquireLatestImage() ?: return
            try {
                val plane = image.planes[0]
                reduceLuminance(plane.buffer, plane.rowStride, plane.pixelStride, width, height, luminance)
            } finally {
                image.close()
            }
            val text = goAheadText(luminance, width, height) ?: return
            finish { found(text) }
        }

        /** On the scanner's thread: the session, the device and the reader closed, the luminance zeroed and dropped. */
        private fun release() {
            session?.close()
            session = null
            device?.close()
            device = null
            reader?.close()
            reader = null
            luminance.fill(0)
            luminance = ByteArray(0)
        }
    }
}
