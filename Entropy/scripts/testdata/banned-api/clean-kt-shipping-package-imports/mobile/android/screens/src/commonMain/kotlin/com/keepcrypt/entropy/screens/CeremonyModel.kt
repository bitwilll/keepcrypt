package com.keepcrypt.entropy.screens

import kotlin.concurrent.Volatile
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// Any shipping file may import the coroutines library's ten names, each by its whole line; the
// standard library's own concurrency package is another package, and a class's .java another name.
private val type = Manager::class.java
