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

  public static byte[] encodeData(final boolean allowed, final String imei, final int timestamp) {
    Log.d(TAG, "encodeData: allowed=[" + allowed + "], imei=[" + imei + "], timestamp=[" + timestamp + "]");

    byte[] origData = new byte[20];

    int byteCount = 0;

    origData[byteCount++] = (byte) (allowed ? 1 : 0);

    for (int i = 0; i < imei.length(); i++) {
      origData[byteCount++] = (byte) imei.charAt(i);
    }

    byte[] timestampBytes = intToBytesBE(timestamp);
    for (int i = 0; i < timestampBytes.length; i++) {
      origData[byteCount++] = timestampBytes[i];
    }

    Log.v(TAG, "encodeData: origData.length=[" + origData.length + "]");

    return origData;
  }

  public static void decodeData(final byte[] origData) {
    Log.d(TAG, "decodeData: origData.length=[" + origData.length + "]");

    boolean allowed = origData[0] != 0;

    byte[] imeiBytes = Arrays.copyOfRange(origData, 1, 16);
    String imei = new String(imeiBytes);

    byte[] timestampBytes = Arrays.copyOfRange(origData, 16, 20);
    int timestamp = bytesToIntBE(timestampBytes);

    Log.v(TAG, "decodeData: allowed=[" + allowed + "], imei=[" + imei + "], timestamp=[" + timestamp + "]");
  }

  public static byte[] signData(final byte[] origData,
                                final PrivateKey privateKey,
                                final String algorithm,
                                final String provider) {
    Log.d(TAG, "signData: origData.length=[" + origData.length + "], algorithm=[" +
        algorithm + "], provider=[" + provider + "]");

    byte[] signedData = null;

    Signature signature = null;
    try {
      signature = Signature.getInstance(algorithm, provider);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }

    try {
      signature.initSign(privateKey);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }

    try {
      signature.update(origData);
    } catch (SignatureException e) {
      e.printStackTrace();
    }

    try {
      signedData = signature.sign();
    } catch (SignatureException e) {
      e.printStackTrace();
    }

    Log.v(TAG, "generateSignature: signedData.length=[" + signedData.length + "]");

    return signedData;
  }

  public static boolean verifyData(final byte[] signedData,
                                   final PublicKey publicKey,
                                   final String algorithm,
                                   final String provider) {
    Log.d(TAG, "verifyData: signedData.length=[" + signedData.length + "], publicKey=[" +
        publicKey + "], algorithm=[" + algorithm + "], provider=[" + provider + "]");

    boolean verified = false;

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
      signature.update(signedData, 0, signedData.length);
    } catch (SignatureException e) {
      e.printStackTrace();
    }

    try {
      verified = signature.verify(signedData);

      Log.v(TAG, "verifyData: verified=[" + verified + "]");
    } catch (SignatureException e) {
      e.printStackTrace();
    }

    return verified;
  }

  // ??? Can this method handle the import of both public and private keys?
  public static Key importKeyFromFile(final String filePath,
                                      final String signatureType,
                                      final String keyType,
                                      final String encodedKeySpecType,
                                      final String fileFormat) {
    Log.d(TAG, "importKeyFromFile: filePath={" + filePath + "], signatureType=[" + signatureType +
        "], keyType=[" + keyType + "], encodedKeySpecType=[" + encodedKeySpecType + "], fileFormat=[" + fileFormat + "]");

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
    if (encodedKeySpecType.equals(ConstantsUtils.X509_ENCODED_KEY_SPEC_TYPE)) {
      keySpec = new X509EncodedKeySpec(keyBytes);
    } else if (encodedKeySpecType.equals(ConstantsUtils.PKCS8_ENCODED_KEY_SPEC_TYPE)) {
      keySpec = new PKCS8EncodedKeySpec(keyBytes);
    } else {
      Log.e(TAG, "importKeyFrom Type: Unsupported encodeKeySpecType=[" + encodedKeySpecType + "]");
      return null;
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

    Log.v(TAG, "importKeyFromFile: key=[" + key + "]");

    return key;
  }

  public static PrivateKey importPrivateKeyFromFile(final String filePath,
                                                    final String signatureType,
                                                    final String keyType,
                                                    final String encodedKeySpecType,
                                                    final String fileFormat) {
    Log.d(TAG, "importPrivateKeyFromFile: filePath={" + filePath + "], signatureType=[" + signatureType +
        "], keyType=[" + keyType + "], encodedKeySpecType=[" + encodedKeySpecType + "], fileFormat=[" + fileFormat + "]");

    PrivateKey key = null;

    Path path = Paths.get(filePath);

    byte[] keyBytes = null;
    try {
      keyBytes = Files.readAllBytes(path);
    } catch (IOException e) {
      e.printStackTrace();
    }

    Log.v(TAG, "importPrivateKeyFromFile: keyBytes.length=[" + keyBytes.length + "]");

    KeySpec keySpec = null;
    if (encodedKeySpecType.equals(ConstantsUtils.X509_ENCODED_KEY_SPEC_TYPE)) {
      keySpec = new X509EncodedKeySpec(keyBytes);
    } else if (encodedKeySpecType.equals(ConstantsUtils.PKCS8_ENCODED_KEY_SPEC_TYPE)) {
      keySpec = new PKCS8EncodedKeySpec(keyBytes);
    } else {
      Log.e(TAG, "importPrivateKeyFrom Type: Unsupported encodeKeySpecType=[" + encodedKeySpecType + "]");
      return null;
    }

    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance(signatureType);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }

    try {
      //if (keyType == ConstantsUtils.PUBLIC_KEY_TYPE) {
      //  key = keyFactory.generatePublic(keySpec);
      //} else if (keyType == ConstantsUtils.PRIVATE_KEY_TYPE) {
      key = keyFactory.generatePrivate(keySpec);
      //}
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    }

    Log.v(TAG, "importPrivateKeyFromFile: key=[" + key + "]");

    return key;
  }

  public static PublicKey importPublicKeyFromFile(final String filePath,
                                                  final String signatureType,
                                                  final String keyType,
                                                  final String encodedKeySpecType,
                                                  final String fileFormat) {
    Log.d(TAG, "importPublicKeyFromFile: filePath={" + filePath + "], signatureType=[" + signatureType +
        "], keyType=[" + keyType + "], encodedKeySpecType=[" + encodedKeySpecType + "], fileFormat=[" + fileFormat + "]");

    PublicKey key = null;

    Path path = Paths.get(filePath);

    byte[] keyBytes = null;
    try {
      keyBytes = Files.readAllBytes(path);
    } catch (IOException e) {
      e.printStackTrace();
    }

    Log.v(TAG, "importPublicKeyFromFile: keyBytes.length=[" + keyBytes.length + "]");

    KeySpec keySpec = null;
    if (encodedKeySpecType.equals(ConstantsUtils.X509_ENCODED_KEY_SPEC_TYPE)) {
      keySpec = new X509EncodedKeySpec(keyBytes);
    } else if (encodedKeySpecType.equals(ConstantsUtils.PKCS8_ENCODED_KEY_SPEC_TYPE)) {
      keySpec = new PKCS8EncodedKeySpec(keyBytes);
    } else {
      Log.e(TAG, "importKeyFrom Type: Unsupported encodeKeySpecType=[" + encodedKeySpecType + "]");
      return null;
    }

    KeyFactory keyFactory = null;
    try {
      keyFactory = KeyFactory.getInstance(signatureType);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }

    try {
      //if (keyType == ConstantsUtils.PUBLIC_KEY_TYPE) {
      key = keyFactory.generatePublic(keySpec);
      //} else if (keyType == ConstantsUtils.PRIVATE_KEY_TYPE) {
      //key = keyFactory.generatePrivate(keySpec);
      //}
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
    }

    Log.v(TAG, "importPublicKeyFromFile: key=[" + key + "]");

    return key;
  }
}
