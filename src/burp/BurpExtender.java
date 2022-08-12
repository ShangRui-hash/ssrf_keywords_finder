package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private String[] SSRFKeywords = new String[]{
            "url",
            "3g",
            "callback",
            "display",
            "domain",
            "imageURL",
            "link",
            "ref",
            "req",
            "share",
            "source",
            "sourceURL",
            "source_url",
            "src",
            "target",
            "u",
            "uri",
            "wap",
            "redirect",
            "server",
            "port",
    };
    ;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("rickshang/ssrf_keywords_finder");
        callbacks.registerScannerCheck(this);
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    // 搜索content中是否有match，如果有，则返回match字符串的(起始位置,终止位置)数组
    private List<int[]> getMatches(byte[] content, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();
        int start = 0;
        while (start < content.length) {
            start = helpers.indexOf(content, match, true, start, content.length);
            if (start == -1)
                break;
            matches.add(new int[]{start, start + match.length});
            start += match.length;
        }
        return matches;
    }

    //搜索有没有名为keyword的参数名
    private List<int[]> getParamMatch(List<IParameter> params, String keyword) {
        List<int[]> matches = new ArrayList<int[]>();
        for (IParameter param : params) {
            String paramName = param.getName();
            if (paramName.equals(keyword)) {
                matches.add(new int[]{param.getNameStart(), param.getNameEnd()});
            }
        }
        return matches;
    }
    //
    // implement IScannerCheck
    //

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        byte[] request = baseRequestResponse.getRequest();
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        List<IParameter> params = requestInfo.getParameters();
        List<IScanIssue> issues = new ArrayList<>(1);
        for (String keyword : SSRFKeywords) {
            List<int[]> matches = getParamMatch(params, keyword);
            if (matches.size() > 0) {
                IHttpService website = baseRequestResponse.getHttpService();
                URL url = requestInfo.getUrl();
                IHttpRequestResponse[] highlightHttpMessages = new IHttpRequestResponse[]{
                        callbacks.applyMarkers(baseRequestResponse, matches, null),
                };
                String issueName = "Potential SSRF parameters";
                String issueDetail = "The request contains the string: " + keyword;
                String severity = "Information";
                CustomScanIssue issue = new CustomScanIssue(website, url, highlightHttpMessages, issueName, issueDetail, severity);
                issues.add(issue);
            }
        }

        if (issues.size() > 0) {
            return issues;
        } else {
            return null;
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }


}


//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue {
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return "Certain";
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

}

