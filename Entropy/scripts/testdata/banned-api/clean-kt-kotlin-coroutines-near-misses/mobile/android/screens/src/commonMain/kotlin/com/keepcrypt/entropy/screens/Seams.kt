package com.keepcrypt.entropy.screens

import kotlin.collections.List
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

// None of these names the standard library's coroutines package: the coroutines library's ten allowed
// lines, the words kotlinx and coroutines alone, the word kotlin alone, a name that starts with it, and
// the standard library's collections and concurrency packages.
private val kotlinCoroutinesNote = "the kotlinx library runs these coroutines"
private val notes: List<String> = kotlin.collections.listOf(kotlinCoroutinesNote)
