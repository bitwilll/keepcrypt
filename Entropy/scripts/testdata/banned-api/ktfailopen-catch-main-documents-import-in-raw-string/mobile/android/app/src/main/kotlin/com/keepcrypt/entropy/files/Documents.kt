// IOException's import line inside a raw string, below the import header, is no import.
val note = """
import java.io.IOException
"""
} catch (e: IOException) {
