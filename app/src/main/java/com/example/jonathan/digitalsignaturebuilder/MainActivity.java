package com.example.jonathan.digitalsignaturebuilder;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.example.jonathan.digitalsignaturebuilder.utils.ConstantsUtils;

import java.security.PrivateKey;
import java.security.PublicKey;

public class MainActivity extends AppCompatActivity {
  private static final String TAG = ConstantsUtils.APP_TAG + MainActivity.class.getSimpleName();

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    Log.d(TAG, "onCreate");

    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    byte[] origData = DigitalSignatureUtils.encodeData(ConstantsUtils.TEST_ALLOWED,
        ConstantsUtils.TEST_IMEI,
        ConstantsUtils.TEST_IMESTAMP);

    // https://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file
    PrivateKey privateKey = DigitalSignatureUtils.importPrivateKeyFromFile(ConstantsUtils.ACCESS_PRIVATE_KEY_DER_FILE_PATH,
        ConstantsUtils.ACCESS_SIGNATURE_TYPE,
        ConstantsUtils.PRIVATE_KEY_TYPE,
        ConstantsUtils.PKCS8_ENCODED_KEY_SPEC_TYPE,
        ConstantsUtils.DER_FILE_FORMAT);

    byte[] signedData = DigitalSignatureUtils.signData(origData,
        privateKey,
        ConstantsUtils.ACCESS_SIGNATURE_ALGORITHM,
        ConstantsUtils.ACCESS_SIGNATURE_PROVIDER);

    // https://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file
    PublicKey publicKey = DigitalSignatureUtils.importPublicKeyFromFile(ConstantsUtils.ACCESS_PUBLIC_KEY_DER_FILE_PATH,
        ConstantsUtils.ACCESS_SIGNATURE_TYPE,
        ConstantsUtils.PUBLIC_KEY_TYPE,
        ConstantsUtils.X509_ENCODED_KEY_SPEC_TYPE,
        ConstantsUtils.DER_FILE_FORMAT);

    DigitalSignatureUtils.verifyData(signedData,
        ConstantsUtils.ACCESS_SIGNATURE_ALGORITHM,
        ConstantsUtils.ACCESS_SIGNATURE_PROVIDER,
        publicKey);

    DigitalSignatureUtils.decodeData(origData);
  }
}
