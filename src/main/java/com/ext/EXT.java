package com.ext;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.ext.scanner.AKSKScanner;
import com.ext.scanner.FastJsonScanner;

import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.Properties;


public class EXT implements BurpExtension {
    LinkedList<HttpResponse> lists = new LinkedList<>();
    MontoyaApi api;
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        initExt("CheckAccessKey");
    }
    public void initExt(String extName){
        InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("config.properties");
        api.logging().logToOutput(System.getProperty("user.dir"));
        Properties properties = new Properties();
        try {
            properties.load(inputStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String token = (String) properties.get("token");
        String prefix = (String) properties.get("prefix");
        // 注册扫描器
        api.scanner().registerScanCheck(new AKSKScanner());
        api.scanner().registerScanCheck(new FastJsonScanner(api,prefix,token));
        api.extension().setName(extName);
        //卸载插件
//        api.extension().registerUnloadingHandler(() -> api.extension().unload());
    }

 }