// NEGATIVE TEST, never merge: the banned-API gate must reject this (rule 1).
package app

fun face(): Int = (Math.random() * 6).toInt() + 1
