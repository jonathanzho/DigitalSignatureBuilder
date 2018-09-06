package com.example.jonathan.digitalsignaturebuilder;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.example.jonathan.digitalsignaturebuilder.utils.ConstantsUtils;

import java.security.PublicKey;

public class MainActivity extends AppCompatActivity {
  private static final String TAG = ConstantsUtils.APP_TAG + MainActivity.class.getSimpleName();

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    Log.d(TAG, "onCreate");

    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    byte [] signature = DigitalSignatureUtils.encodeSignature(ConstantsUtils.TEST_ALLOWED,
        ConstantsUtils.TEST_IMEI,
        ConstantsUtils.TEST_IMESTAMP);

    PublicKey publicKey = (PublicKey) DigitalSignatureUtils.importKeyFromFile(ConstantsUtils.ACCESS_PUBLIC_KEY_DER_FILE_PATH,
        ConstantsUtils.ACCESS_SIGNATURE_TYPE,
        ConstantsUtils.PUBLIC_KEY_TYPE,
        ConstantsUtils.DER_FILE_FORMAT);

    DigitalSignatureUtils.decodeSignature(signature,
        ConstantsUtils.ACCESS_SIGNATURE_ALGORITHM,
        ConstantsUtils.ACCESS_SIGNATURE_PROVIDER,
        publicKey);
  }
}
