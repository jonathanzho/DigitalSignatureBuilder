package com.example.jonathan.digitalsignaturebuilder;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.example.jonathan.digitalsignaturebuilder.utils.ConstantsUtils;

public class MainActivity extends AppCompatActivity {
  private static final String TAG = ConstantsUtils.APP_TAG + MainActivity.class.getSimpleName();

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    Log.d(TAG, "onCreate");

    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    byte [] signature = DigitalSignatureUtils.encodeSignature(ConstantsUtils.ALLOWED,
        ConstantsUtils.IMEI,
        ConstantsUtils.TIMESTAMP);

    DigitalSignatureUtils.decodeSignature(signature);
  }
}
