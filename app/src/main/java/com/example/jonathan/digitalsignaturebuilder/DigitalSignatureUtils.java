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
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

    PrivateKey privateKey = (PrivateKey) importKeyFromFile(ConstantsUtils.ACCESS_PRIVATE_KEY_DER_FILE_PATH,
        ConstantsUtils.ACCESS_SIGNATURE_TYPE,
        ConstantsUtils.PRIVATE_KEY_TYPE,
        ConstantsUtils.DER_FILE_FORMAT);

    byte[] outSignature = generateSignature(ConstantsUtils.ACCESS_SIGNATURE_ALGORITHM,
        ConstantsUtils.ACCESS_SIGNATURE_PROVIDER,
        privateKey,
        inSignature);

    return outSignature;
  }

  public static void decodeSignature(final byte[] inSignature,
                                     final String algorithm,
                                     final String provider,
                                     final PublicKey publicKey) {
    Log.d(TAG, "decodeSignature: inSignature.length=[" + inSignature.length + "], algorithm=[" + algorithm +
        "], provider=[" + provider + "], publicKey=[" + publicKey + "]");

    Signature signature = null;
    try {
      signature = Signature.getInstance(algorithm, provider);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
    }

    try {
      signature.initVerify(publicKey);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }

    try {
      signature.update(inSignature, 0, inSignature.length);
    } catch (SignatureException e) {
      e.printStackTrace();
    }

    try {
      boolean verified = signature.verify(inSignature);

      Log.v(TAG, "decodeSignature: verified=[" + verified + "]");
    } catch (SignatureException e) {
      e.printStackTrace();
    }


    boolean allowed = inSignature[0] != 0;

    byte[] imeiBytes = Arrays.copyOfRange(inSignature, 1, 16);
    String imei = new String(imeiBytes);

    byte[] timestampBytes = Arrays.copyOfRange(inSignature, 16, 20);
    int timestamp = bytesToIntBE(timestampBytes);

    Log.v(TAG, "decodeSignature: allowed=[" + allowed + "], imei=[" + imei + "], timestamp=[" + timestamp + "]");
  }

  public static Key importKeyFromFile(final String filePath,
                                      final String signatureType,
                                      final int keyType,
                                      final int fileFormat) {
    Log.d(TAG, "importKeyFromFile: filePath={" + filePath + "], signatureType=[" + signatureType +
        "], keyType=[" + keyType + "], fileFormat=[" + fileFormat + "]");

    Key key = null;

    Path path = Paths.get(filePath);

    byte[] keyBytes = null;
    try {
      keyBytes = Files.readAllBytes(path);
    } catch (IOException e) {
      e.printStackTrace();
    }

    Log.v(TAG, "importKeyFromFile: keyBytes.length=[" + keyBytes.length + "]");

    KeySpec keySpec = null;
    if (fileFormat == ConstantsUtils.PEM_FILE_FORMAT) {
      keySpec = new X509EncodedKeySpec(keyBytes);
    } else if (fileFormat == ConstantsUtils.DER_FILE_FORMAT) {
      keySpec = new PKCS8EncodedKeySpec(keyBytes);
    }

    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance(signatureType);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }

    try {
      if (keyType == ConstantsUtils.PUBLIC_KEY_TYPE) {
        key = keyFactory.generatePublic(keySpec);
      } else if (keyType == ConstantsUtils.PRIVATE_KEY_TYPE) {
        key = keyFactory.generatePrivate(keySpec);
      }
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    }

    Log.v(TAG, "importKeyFromFile: key={" + key + "]");

    return key;
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
