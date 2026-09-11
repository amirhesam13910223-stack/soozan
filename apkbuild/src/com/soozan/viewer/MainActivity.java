package com.soozan.viewer;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.webkit.DownloadListener;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

public class MainActivity extends Activity {
    private WebView web;
    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        // 🛡️ مسدودسازی اسکرین‌شات و ضبط صفحه در سطح اندروید
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                             WindowManager.LayoutParams.FLAG_SECURE);
        prefs = getSharedPreferences("soozan", MODE_PRIVATE);
        // اولین صفحه = ورود آیدی (سرور پیش‌فرض لوکال)
        startWeb(prefs.getString("server", "http://127.0.0.1:8000"));
    }

    private void showSetup() {
        LinearLayout lay = new LinearLayout(this);
        lay.setOrientation(LinearLayout.VERTICAL);
        lay.setBackgroundColor(0xFF070B14);
        lay.setPadding(70, 140, 70, 70);
        final EditText et = new EditText(this);
        et.setHint("http://127.0.0.1:8000");
        et.setText(prefs.getString("server", ""));
        et.setTextColor(0xFFEEF2FF);
        et.setHintTextColor(0xFF5F6C93);
        et.setBackgroundColor(0xFF0F1730);
        et.setPadding(30, 30, 30, 30);
        Button btn = new Button(this);
        btn.setText("اتصال به سوزان 🔥");
        btn.setBackgroundColor(0xFFFF6B35);
        btn.setTextColor(0xFFFFFFFF);
        btn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String u = et.getText().toString().trim();
                if (u.isEmpty()) return;
                if (!u.startsWith("http")) u = "http://" + u;
                prefs.edit().putString("server", u).apply();
                startWeb(u);
            }
        });
        lay.addView(et); lay.addView(btn);
        setContentView(lay);
    }

    private void showError() {
        LinearLayout lay = new LinearLayout(this);
        lay.setOrientation(LinearLayout.VERTICAL);
        lay.setBackgroundColor(0xFF070B14);
        lay.setPadding(70, 200, 70, 70);
        android.widget.TextView tv = new android.widget.TextView(this);
        tv.setText("🔌 اتصال به سرور برقرار نشد");
        tv.setTextColor(0xFFEEF2FF);
        tv.setTextSize(18);
        tv.setGravity(android.view.Gravity.CENTER);
        Button retry = new Button(this);
        retry.setText("تلاش مجدد");
        retry.setBackgroundColor(0xFFFF6B35);
        retry.setTextColor(0xFFFFFFFF);
        retry.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                startWeb(prefs.getString("server", "http://127.0.0.1:8000"));
            }
        });
        Button cfg = new Button(this);
        cfg.setText("تنظیم سرور");
        cfg.setBackgroundColor(0xFF0F1730);
        cfg.setTextColor(0xFFEEF2FF);
        cfg.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) { showSetup(); }
        });
        lay.addView(tv); lay.addView(retry); lay.addView(cfg);
        setContentView(lay);
    }

    private void startWeb(String url) {
        if (url.endsWith("/")) url = url.substring(0, url.length() - 1);
        web = new WebView(this);
        web.setBackgroundColor(0xFF070B14);
        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setCacheMode(WebSettings.LOAD_NO_CACHE);
        // 🛡️ سخت‌سازی امنیتی وب‌ویو
        ws.setAllowFileAccess(false);
        ws.setAllowContentAccess(false);
        ws.setAllowFileAccessFromFileURLs(false);
        ws.setAllowUniversalAccessFromFileURLs(false);
        web.setLongClickable(false);
        web.setOnLongClickListener(new View.OnLongClickListener() {
            @Override public boolean onLongClick(View v) { return true; }
        });
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String u) {
                String host = prefs.getString("server", "");
                if (u.startsWith(host) || u.startsWith("http://127.0.0.1")
                    || u.startsWith("http://localhost")) return false;
                Toast.makeText(MainActivity.this,
                    "دسترسی به آدرس‌های خارجی مسدود است", Toast.LENGTH_SHORT).show();
                return true;
            }

            @Override
            public void onReceivedError(WebView view, int code, String desc, String failingUrl) {
                showError();
            }
        });
        // 🛡️ مسدودسازی کامل دانلود
        web.setDownloadListener(new DownloadListener() {
            @Override public void onDownloadStart(String u, String ua, String cd, String mt, long len) {
                Toast.makeText(MainActivity.this,
                    "دریافت فایل در سوزان غیرفعال است", Toast.LENGTH_SHORT).show();
            }
        });
        setContentView(web);
        web.loadUrl(url + "/i");
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) web.goBack(); else super.onBackPressed();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu m) {
        m.add(0, 1, 0, "تغییر سرور");
        m.add(0, 2, 0, "خروج");
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem i) {
        if (i.getItemId() == 1) { showSetup(); return true; }
        if (i.getItemId() == 2) { finish(); return true; }
        return super.onOptionsItemSelected(i);
    }
}
