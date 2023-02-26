package com.ext.scanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;


import java.util.ArrayList;
import java.util.List;

public class AKSKScanner implements ScanCheck {
    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        return checkResponse(baseRequestResponse);
    }
    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        return checkResponse(baseRequestResponse);
    }
    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        if (newIssue.baseUrl() == existingIssue.baseUrl()) return null;
        return ConsolidationAction.KEEP_BOTH;
    }
    static List<AuditIssue> list = new ArrayList<>();
    private static final String[] keyWord = new String[]{"ALIYUN_ACCESSKEYID","ALIYUN_ACCESSKEYSECRET","ACCESSKEYID","ACCESSKEYSECRET","AccessKey","AccessSecret"};
    public  AuditResult checkResponse(HttpRequestResponse httpRequestResponse){
        checkAKSK(httpRequestResponse);
        return AuditResult.auditResult(list);
    }

    /***
     * 检查响应结果，是否存在key泄露
     * @param httpRequestResponse httpRequestResponse对象
     */
    public void checkAKSK(HttpRequestResponse httpRequestResponse){
        for (String s : keyWord) {
            if (httpRequestResponse.response().bodyToString().toLowerCase().contains(s.toLowerCase())){
                AuditIssue auditIssue = AuditIssue.auditIssue("ACCESSKEYID LEAK","THERE MAY BE AN ACCESSKEYID LEAK","",httpRequestResponse.url(), AuditIssueSeverity.HIGH
                        , AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,httpRequestResponse);
                list.add(auditIssue);
            }
        }
    }

}
