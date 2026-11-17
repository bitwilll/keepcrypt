package com.keepcrypt.entropy.camera
// import java.util.concurrent.Executor
val callbacks = Executor { camera.post(it) }
