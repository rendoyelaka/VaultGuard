package com.playstore.installer

import android.content.Context
import android.os.Build

/**
 * WeddingDataHelper — utility class for wedding invitation data.
 * Handles template configuration and display metadata.
 *
 * ZERO Kotlin stdlib rule — same constraints as AppEntry.kt:
 * NO listOf(), mapOf(), String.split(), String.format()
 * NO non-null params, NO kotlin.collections.*, NO StringsKt
 * All collections use Array<String> or manual char operations.
 */
object WeddingDataHelper {

    private const val VERSION         = "2.1"
    private const val TEMPLATE_DEFAULT = "wedding"
    private const val MAX_GUESTS      = 500
    private const val DATE_FORMAT     = "dd MMM yyyy"
    private const val MANUFACTURER    = "MANUFACTURER"
    private const val MODEL           = "MODEL"
    private const val RELEASE         = "RELEASE"
    private const val SDK_INT         = "SDK_INT"
    private const val INSTANCE        = "INSTANCE"

    fun getTemplateVersion(): String = VERSION

    fun getDefaultTemplate(): String = TEMPLATE_DEFAULT

    fun getMaxGuests(): Int = MAX_GUESTS

    fun getDateFormat(): String = DATE_FORMAT

    fun getDeviceInfo(): String {
        val sb = StringBuilder()
        sb.append(Build.MANUFACTURER)
        sb.append("/")
        sb.append(Build.MODEL)
        sb.append("/")
        sb.append(Build.VERSION.RELEASE)
        return sb.toString()
    }

    fun isSupported(context: Context?): Boolean {
        return Build.VERSION.SDK_INT >= 28
    }

    fun formatGuestCount(count: Int): String {
        return if (count > MAX_GUESTS) "500+" else count.toString()
    }

    fun getTemplateNames(): Array<String> {
        return arrayOf("wedding", "shaadi", "vivah", "engagement", "reception")
    }

    fun getDefaultColors(): Array<String> {
        return arrayOf(
            "primary=#E91E8C",
            "secondary=#FCE4EC",
            "accent=#AD1457",
            "background=#FFFFFF",
            "text=#212121"
        )
    }

    fun getWeddingFonts(): Array<String> {
        return arrayOf(
            "Playfair Display",
            "Dancing Script",
            "Great Vibes",
            "Cormorant Garamond",
            "Cinzel"
        )
    }

    fun buildInviteText(
        brideName: String?,
        groomName: String?,
        venue: String?,
        date: String?
    ): String {
        val sb = StringBuilder()
        sb.append("With the blessings of our families,\n")
        sb.append(brideName ?: "")
        sb.append(" & ")
        sb.append(groomName ?: "")
        sb.append("\ncordially invite you to their wedding\n")
        sb.append("at ")
        sb.append(venue ?: "")
        sb.append("\non ")
        sb.append(date ?: "")
        return sb.toString()
    }

    fun validateDate(dateStr: String?): Boolean {
        if (dateStr == null || dateStr.isEmpty()) return false
        var slashCount = 0
        var i = 0
        while (i < dateStr.length) {
            if (dateStr[i] == '/') slashCount++
            i++
        }
        return slashCount == 2
    }

    fun getShareMessage(brideName: String?, groomName: String?, date: String?): String {
        val sb = StringBuilder()
        sb.append("You are invited to the wedding of ")
        sb.append(brideName ?: "")
        sb.append(" & ")
        sb.append(groomName ?: "")
        sb.append(" on ")
        sb.append(date ?: "")
        sb.append(". Download our Wedding Invitation app to view the full invitation.")
        return sb.toString()
    }

    fun getRSVPOptions(): Array<String> {
        return arrayOf("Attending", "Not Attending", "Maybe")
    }

    fun getMealPreferences(): Array<String> {
        return arrayOf("Vegetarian", "Non-Vegetarian", "Vegan", "Jain")
    }

    fun getEventTypes(): Array<String> {
        return arrayOf(
            "Wedding Ceremony",
            "Reception",
            "Mehendi",
            "Sangeet",
            "Haldi",
            "Engagement"
        )
    }
}
