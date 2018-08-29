package com.example.jonathan.digitalsignaturebuilder;

import android.util.Log;

import com.example.jonathan.digitalsignaturebuilder.utils.ConstantsUtils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class DigitalSignatureUtils {
  private static final String TAG = ConstantsUtils.APP_TAG + DigitalSignatureUtils.class.getSimpleName();

  public static byte[] intToBytesBE(final int inInt) {
    return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(inInt).array();
  }

  public static int bytesToIntBE(final byte[] inBytes) {
    return ByteBuffer.wrap(inBytes).getInt();    // Big Endian by default
  }

  public static byte[] encodeSignature(final boolean allowed, final String imei, final int timestamp) {
    Log.d(TAG, "encodeSignature: allowed=[" + allowed + "], imei=[" + imei + "], timestamp=[" + timestamp + "]");

    byte[] signature = new byte[20];

    int byteCount = 0;

    signature[byteCount++] = (byte) (allowed ? 1 : 0);

    for (int i = 0; i < imei.length(); i++) {
      signature[byteCount++] = (byte) imei.charAt(i);
    }

    byte[] timestampBytes = intToBytesBE(timestamp);
    for (int i = 0; i < timestampBytes.length; i++) {
      signature[byteCount++] = timestampBytes[i];
    }

    return signature;
  }

  public static void decodeSignature(final byte[] signature) {
    Log.d(TAG, "decodeSignature: signature.length=[" + signature.length + "]");

    boolean allowed = signature[0] != 0;

    byte[] imeiBytes = Arrays.copyOfRange(signature, 1, 16);
    String imei = new String(imeiBytes);

    byte[] timestampBytes = Arrays.copyOfRange(signature, 16, 20);
    int timestamp = bytesToIntBE(timestampBytes);

    Log.v(TAG, "decodeSignature: allowed=[" + allowed + "], imei=[" + imei + "], timestamp=[" + timestamp + "]");
  }
}
