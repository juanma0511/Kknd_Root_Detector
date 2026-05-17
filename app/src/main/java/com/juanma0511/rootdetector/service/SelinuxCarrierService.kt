package com.juanma0511.rootdetector.service

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel

class SelinuxCarrierService : Service() {

    private val binder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code == IBinder.FIRST_CALL_TRANSACTION) {
                reply?.writeString(preloadedPayload)
                return true
            }
            return super.onTransact(code, data, reply, flags)
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    companion object {
        @Volatile
        private var preloadedPayload: String? = null

        fun setPreloadedPayload(payload: String) {
            preloadedPayload = payload
        }
    }
}
