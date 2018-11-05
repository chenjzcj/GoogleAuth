package com.felix.googleauth;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import com.felix.googleauthlibrary.GoogleAuthHelper;


public class MainActivity extends AppCompatActivity {

    private EditText etActiveCode;
    private Button btnActive;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etActiveCode = findViewById(R.id.et_active_code);
        btnActive = findViewById(R.id.btn_active);

        btnActive.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String activeCode = etActiveCode.getText().toString().trim();
                if (TextUtils.isEmpty(activeCode)) {
                    Toast.makeText(MainActivity.this, "输入不能为空", Toast.LENGTH_LONG).show();
                    return;
                }
                boolean verify = GoogleAuthHelper.verifyNoExcursionForAndroid(GoogleAuthHelper.secretKeyDefalut, activeCode);
                Toast.makeText(MainActivity.this, verify ? "验证成功" : "验证失败", Toast.LENGTH_LONG).show();
            }
        });
    }
}
