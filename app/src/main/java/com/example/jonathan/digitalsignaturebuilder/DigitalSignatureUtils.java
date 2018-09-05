package com.example.jonathan.digitalsignaturebuilder;

import android.util.Log;

import com.example.jonathan.digitalsignaturebuilder.utils.ConstantsUtils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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

    byte[] inSignature = new byte[20];

    int byteCount = 0;

    inSignature[byteCount++] = (byte) (allowed ? 1 : 0);

    for (int i = 0; i < imei.length(); i++) {
      inSignature[byteCount++] = (byte) imei.charAt(i);
    }

    byte[] timestampBytes = intToBytesBE(timestamp);
    for (int i = 0; i < timestampBytes.length; i++) {
      inSignature[byteCount++] = timestampBytes[i];
    }

    PrivateKey privateKey = importPrivateKeyFromFile(ConstantsUtils.ACCESS_PRIVATE_KEY_FILE_PATH,
        ConstantsUtils.ACCESS_SIGNATURE_TYPE);

    byte[] outSignature = inSignature;
/*
    byte[] outSignature = generateSignature(ConstantsUtils.ACCESS_SIGNATURE_ALGORITHM,
        ConstantsUtils.ACCESS_SIGNATURE_PROVIDER,
        privateKey,
        inSignature);
*/
    return outSignature;
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

  private static PrivateKey importPrivateKeyFromFile(final String filePath, final String type) {
    Log.d(TAG, "importPrivateKeyFromFile: filePath={" + filePath + "], type=[" + type + "]");

    PrivateKey privateKey = null;

    Path path = Paths.get(filePath);

    try {
      byte[] privateBytes = Files.readAllBytes(path);

      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);

      try {
        KeyFactory keyFactory = KeyFactory.getInstance(type);

        try {
          privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
          e.printStackTrace();
        }
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
      }


    } catch (IOException e) {
      e.printStackTrace();
    }

    Log.v(TAG, "importPrivateKeyFromFile: privateKey={" + privateKey + "]");

    return privateKey;
  }

  private static byte[] generateSignature(final String algorithm,
                                        final String provider,
                                        final PrivateKey privateKey,
                                        final byte[] inSignature) {
    Log.d(TAG, "generateSignature: algorithm=[" + algorithm + "], provider=[" + provider + "], privateKey=[" +
        privateKey + "], inSignature.length=[" + inSignature.length + "]");

    byte[] outSignature = null;

    try {
      Signature signature = Signature.getInstance(algorithm, provider);
      try {
        signature.initSign(privateKey);
        try {
          signature.update(inSignature);

          outSignature = signature.sign();
        } catch (SignatureException e) {
          e.printStackTrace();
        }
      } catch (InvalidKeyException e) {
        e.printStackTrace();
      }
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
    }

    Log.v(TAG, "generateSignature: outSignature.length=[" + outSignature.length + "]");

    return outSignature;
  }
}
