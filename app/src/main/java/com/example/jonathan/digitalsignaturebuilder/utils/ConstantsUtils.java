package com.example.jonathan.digitalsignaturebuilder.utils;

public class ConstantsUtils {
  public static final String APP_TAG = " DSB ";

  public static final boolean TEST_ALLOWED = true;
  public static final String TEST_IMEI = "123456789012345";
  public static final int TEST_IMESTAMP = 1546300799;

  public static final String PUBLIC_KEY_TYPE = "public";
  public static final String PRIVATE_KEY_TYPE = "private";

  public static final String X509_ENCODED_KEY_SPEC_TYPE = "X509";
  public static final String PKCS8_ENCODED_KEY_SPEC_TYPE = "PKCS8";

  public static final String PEM_FILE_FORMAT = "pem";
  public static final String DER_FILE_FORMAT = "der";

  public static final String ACCESS_PUBLIC_KEY_DER_FILE_PATH = "/sdcard/Download/access-public-key.der";
  public static final String ACCESS_PRIVATE_KEY_DER_FILE_PATH = "/sdcard/Download/access-private-key.der";
  public static final String ACCESS_PUBLIC_KEY_PEM_FILE_PATH = "/sdcard/Download/access-public-key.pem";
  public static final String ACCESS_PRIVATE_KEY_PEM_FILE_PATH = "/sdcard/Download/access-private-key.pem";
  public static final String ACCESS_SIGNATURE_TYPE = "EC";
  public static final String ACCESS_SIGNATURE_ALGORITHM = "SHA256withECDSA";
  public static final String ACCESS_SIGNATURE_PROVIDER = "BC";
}
