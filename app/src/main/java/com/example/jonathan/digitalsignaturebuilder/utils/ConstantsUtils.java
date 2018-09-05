package com.example.jonathan.digitalsignaturebuilder.utils;

public class ConstantsUtils {
  public static final String APP_TAG = " DSB ";

  public static final boolean TEST_ALLOWED = true;
  public static final String TEST_IMEI = "123456789012345";
  public static final int TEST_IMESTAMP = 1546300799;

  public static final int PUBLIC_KEY_TYPE = 1;
  public static final int PRIVATE_KEY_TYPE = 2;

  public static final String ACCESS_PUBLIC_KEY_FILE_PATH = "/sdcard/Download/access-public-key.der";
  public static final String ACCESS_PRIVATE_KEY_FILE_PATH = "/sdcard/Download/access-private-key.der";
  public static final String ACCESS_SIGNATURE_TYPE = "EC";
  public static final String ACCESS_SIGNATURE_ALGORITHM = "SHA256withECDSA";
  public static final String ACCESS_SIGNATURE_PROVIDER = "BC";
}
